package com.tunaforce.gateway.filter;

import com.tunaforce.gateway.client.UserClient;
import com.tunaforce.gateway.dto.request.UserInfoRequestDto;
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
        // Bypass authentication for all /auth/** and only GET /users (list/search)
        if (path.startsWith("/auth") || (HttpMethod.GET.equals(httpMethod) && path.startsWith("/users"))) {
            log.info("[GW][BYPASS] {} {} (public endpoint)", method, path);
            return chain.filter(exchange);
        }

        String token = extractToken(exchange);
        if (token == null) {
            log.warn("[GW][AUTH] Missing Authorization header: {} {}", method, path);
        }

        Claims claims = parseClaims(token);
        if (claims == null || claims.getSubject() == null || claims.getSubject().isEmpty()) {
            log.warn("[GW][AUTH] Invalid or missing JWT. path={}, method={}, tokenPresent={}", path, method, token != null);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String subject = claims.getSubject();
        String rolesHeader = claims.get("role", String.class);

        // ==== Authorization by role & path (coarse-grained) ====
        // NOTE: You can refine allowed URL prefixes below. Keep it simple here and adjust later.
        // Policy summary:
        // - MASTER: all URLs allowed
        // - DELIVERY: hubs, hub-routes, orders, messages
        // - COMPANY: products, companies, orders
        // - HUB: hubs, hub-routes, companies
        String accessTag = getAccessTag(rolesHeader, path);
        if (accessTag == null) {
            log.warn("[GW][AUTHZ DENY] {} {} role={} -> path not allowed", method, path, rolesHeader);
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            return exchange.getResponse().setComplete();
        }
        log.info("[GW][AUTHZ ALLOW] {} {} role={} tag={}", method, path, rolesHeader, accessTag);

        Mono<Tuple2<UserInfoRequestDto, String>> userWithSource = userClient.getUser(subject, token)
                .map(u -> Tuples.of(u, "user-service"))
                .timeout(Duration.ofMillis(userClientTimeoutMs))
                .doOnNext(t -> log.debug("[GW][AUTH] UserClient success for subject={}, loginId={}", subject, t.getT1().userLoginId()))
                .onErrorResume(e -> {
                    log.warn("[GW][AUTH] UserClient.getUser error: {}. Using token claims.", e.toString());
                    return Mono.just(Tuples.of(fallbackFromClaims(claims), "token-claims(error)"));
                })
                .defaultIfEmpty(Tuples.of(fallbackFromClaims(claims), "token-claims(empty)"));

        return userWithSource.flatMap(tuple -> {
            UserInfoRequestDto user = tuple.getT1();
            String source = tuple.getT2();
            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate().headers(h -> {
                // Remove any client-sent spoofable headers
                h.remove("X-User-Id");
                h.remove("X-Roles");
                h.remove("X-Tenant");
                h.remove("X-Login-Id");
                h.remove("X-Username");
                h.remove("X-Slack-Id");
                h.remove("X-Tel");
                h.remove("X-Source");

                // From AuthService login: subject=userId(UUID as String), role=single string claim
                if (subject != null && !subject.isEmpty()) {
                    h.add("X-User-Id", subject);
                }

                // role is mandatory in token
                h.add("X-Roles", rolesHeader);
                h.add("X-Source", source);

                // Propagate additional user fields when available
                if (user.userLoginId() != null && !user.userLoginId().isEmpty()) {
                    h.add("X-Login-Id", user.userLoginId());
                }
                if (user.username() != null && !user.username().isEmpty()) {
                    h.add("X-Username", user.username());
                }
                if (user.slackId() != null && !user.slackId().isEmpty()) {
                    h.add("X-Slack-Id", user.slackId());
                }
                if (user.tel() != null && !user.tel().isEmpty()) {
                    h.add("X-Tel", user.tel());
                }
            }).build();

            log.info("[GW][AUTH OK] {} {} userId={} role={} source={} loginId={}",
                    method, path, subject, rolesHeader, source, user.userLoginId());
            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        });
    }

    // Return a non-null tag if allowed; null if denied. Adjust prefixes as needed.
    private String getAccessTag(String role, String rawPath) {
        if (role == null || role.isBlank()) return null;
        String r = role.toUpperCase();
        String path = (rawPath == null) ? "/" : rawPath.toLowerCase();

        // Public endpoints already bypassed above (e.g., /auth/login, /auth/signup)

        // MASTER: allow everything
        switch (r) {
            case "MASTER" -> {
                return "MASTER-ALL";
            }

            // Helper: path prefix checks (EDIT HERE to refine URL scopes)
            // DELIVERY allowed: /hubs/**, /hub-routes/**, /orders/**, /messages/**
            case "DELIVERY" -> {
                if (startsWithAny(path, "/hubs", "/hub-routes", "/orders", "/messages"))
                    return "DELIVERY{hubs,hub-routes,orders,messages}";
                return null;
            }


            // COMPANY allowed: /products/**, /companies/**, /orders/**
            case "COMPANY" -> {
                if (startsWithAny(path, "/products", "/companies", "/orders", "/messages"))
                    return "COMPANY{products,companies,orders}";
                return null;
            }


            // HUB allowed: /hubs/**, /hub-routes/**, /companies/**
            case "HUB" -> {
                if (startsWithAny(path, "/hubs", "/hub-routes", "/companies", "/messages"))
                    return "HUB{hubs,hub-routes,companies}";
                return null;
            }
        }

        // Unknown role → deny
        return null;
    }

    private boolean startsWithAny(String path, String... prefixes) {
        for (String p : prefixes) {
            if (path.startsWith(p)) return true;
        }
        return false;
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

    private UserInfoRequestDto fallbackFromClaims(Claims claims) {
        // AuthService issues tokens with subject = userId(UUID string) and a single "role" claim.
        String subject = claims.getSubject();
        String role = claims.get("role", String.class);

        java.util.UUID uuid = null;
        try {
            uuid = java.util.UUID.fromString(subject);
        } catch (Exception ignore) {
        }

        // loginId, username, slackId, tel are not present in token → set to null in fallback
        return new UserInfoRequestDto(uuid, null, null, role, null, null);
    }

    // no-op: role is mandatory in token, no extraction helper required

    private String extractToken(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }

        return null;
    }
}
