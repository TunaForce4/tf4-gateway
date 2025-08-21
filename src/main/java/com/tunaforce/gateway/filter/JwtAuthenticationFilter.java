package com.tunaforce.gateway.filter;

import com.tunaforce.gateway.client.UserClient;
import com.tunaforce.gateway.dto.request.UserInfoRequestDto;
import com.tunaforce.gateway.security.RoleAccessPolicy;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuple2;
import reactor.util.function.Tuples;

import javax.crypto.SecretKey;
import java.time.Duration;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter {
    @Value("${service.jwt.secret-key}")
    private String secretKey;

    // Configurable timeout for calling Auth's internal user endpoint
    @Value("${service.user-client.timeout-ms:2000}")
    private long userClientTimeoutMs;

    private final UserClient userClient;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        String path = exchange.getRequest().getURI().getPath();
        HttpMethod httpMethod = exchange.getRequest().getMethod();
        String method = httpMethod.name();

        // 1) 공개 경로 우회
        if (isBypass(path, httpMethod)) {
            log.info("[GW][BYPASS] {} {} (공개 경로)", method, path);
            return chain.filter(exchange);
        }

        // 2) 토큰 파싱 및 기본 검증
        String token = extractToken(exchange);
        if (token == null) log.warn("[GW][AUTH] Authorization 헤더 없음: {} {}", method, path);
        Claims claims = parseClaims(token);
        if (!isValidClaims(claims)) {
            log.warn("[GW][AUTH] JWT 무효 또는 누락. path={}, method={}, tokenPresent={}", path, method, token != null);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // 3) 역할-경로 접근 허용 확인
        String subject = claims.getSubject();
        String rolesHeader = claims.get("role", String.class);
        String accessTag = RoleAccessPolicy.getAccessTag(rolesHeader, path);
        if (accessTag == null) {
            log.warn("[GW][AUTHZ DENY] {} {} role={} -> 허용되지 않은 경로", method, path, rolesHeader);
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            return exchange.getResponse().setComplete();
        }
        log.info("[GW][AUTHZ ALLOW] {} {} role={} tag={}", method, path, rolesHeader, accessTag);

        // 4) 내부 사용자 조회(+타임아웃/폴백) 후 헤더 주입
        Mono<Tuple2<UserInfoRequestDto, String>> userWithSource = getUserWithFallback(subject, token, claims);

        return userWithSource.flatMap(tuple -> {
            UserInfoRequestDto user = tuple.getT1();
            String source = tuple.getT2();

            // 삭제 사용자 차단 (내부 조회 성공 시에만 의미 있음)
            if (user.deletedAt() != null || user.deletedBy() != null) {
                log.warn("[GW][AUTHZ DENY] {} {} userId={} 삭제된 사용자 (deletedAt={}, deletedBy={})", method, path, subject, user.deletedAt(), user.deletedBy());
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }

            ServerHttpRequest mutatedRequest = buildMutatedRequest(exchange, subject, rolesHeader, source, user);
            log.info("[GW][AUTH OK] {} {} userId={} role={} source={} loginId={}", method, path, subject, rolesHeader, source, user.userLoginId());
            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        });
    }

    // ===== 내부 유틸 메서드 =====

    // 공개 경로 우회 규칙
    private boolean isBypass(String path, HttpMethod httpMethod) {
        return path.startsWith("/auth") || (HttpMethod.GET.equals(httpMethod) && path.startsWith("/users"));
    }

    private Claims parseClaims(String token) {
        try {
            SecretKey key =
                    Keys.hmacShaKeyFor(io.jsonwebtoken.io.Decoders.BASE64.decode(secretKey));
            return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
        } catch (Exception e) {
            log.warn("JWT parse failed", e);
            return null;
        }
    }

    // 클레임 기본 검증
    private boolean isValidClaims(Claims claims) {
        return claims != null && claims.getSubject() != null && !claims.getSubject().isEmpty();
    }

    private UserInfoRequestDto fallbackFromClaims(Claims claims) {
        // AuthService issues tokens with subject = userId(UUID string) and a single "role" claim.
        String subject = claims.getSubject();
        String role = claims.get("role", String.class);

        java.util.UUID uuid = null;
        try {
            uuid = java.util.UUID.fromString(subject);
        } catch (Exception ignore) {
        }

        // 토큰엔 상세 정보가 없으므로 null로 채움
        return new UserInfoRequestDto(uuid, null, null, role, null, null, null, null);
    }

    // no-op: role is mandatory in token, no extraction helper required

    private String extractToken(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }

        return null;
    }

    // 내부 사용자 조회 + 타임아웃 + 폴백 처리
    private Mono<Tuple2<UserInfoRequestDto, String>> getUserWithFallback(String subject, String token, Claims claims) {
        return userClient.getUser(subject, token)
                .map(u -> Tuples.of(u, "user-service"))
                .timeout(Duration.ofMillis(userClientTimeoutMs))
                .doOnNext(t -> log.debug("[GW][AUTH] UserClient success for subject={}, loginId={}", subject, t.getT1().userLoginId()))
                .onErrorResume(e -> {
                    log.warn("[GW][AUTH] UserClient.getUser error: {}. Using token claims.", e.toString());
                    return Mono.just(Tuples.of(fallbackFromClaims(claims), "token-claims(error)"));
                })
                .defaultIfEmpty(Tuples.of(fallbackFromClaims(claims), "token-claims(empty)"));
    }

    // 요청 헤더 정리 및 인증 정보 재주입
    private ServerHttpRequest buildMutatedRequest(ServerWebExchange exchange,
                                                 String subject,
                                                 String rolesHeader,
                                                 String source,
                                                 UserInfoRequestDto user) {
        return exchange.getRequest().mutate().headers(h -> {
            // 클라이언트가 임의로 보낸 민감 헤더 제거
            h.remove("X-User-Id");
            h.remove("X-Roles");
            h.remove("X-Tenant");
            h.remove("X-Login-Id");
            h.remove("X-Username");
            h.remove("X-Slack-Id");
            h.remove("X-Tel");
            h.remove("X-Source");

            // 토큰에서 가져온 사용자/역할 주입
            if (subject != null && !subject.isEmpty()) h.add("X-User-Id", subject);
            h.add("X-Roles", rolesHeader);
            h.add("X-Source", source);

            // 내부 조회로 얻은 추가 사용자 정보 전달(있을 때만)
            if (user.userLoginId() != null && !user.userLoginId().isEmpty()) h.add("X-Login-Id", user.userLoginId());
            if (user.username() != null && !user.username().isEmpty()) h.add("X-Username", user.username());
            if (user.slackId() != null && !user.slackId().isEmpty()) h.add("X-Slack-Id", user.slackId());
            if (user.tel() != null && !user.tel().isEmpty()) h.add("X-Tel", user.tel());
        }).build();
    }
}
