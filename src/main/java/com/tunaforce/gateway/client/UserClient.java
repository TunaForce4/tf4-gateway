package com.tunaforce.gateway.client;

import com.tunaforce.gateway.dto.request.UserInfoRequestDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
@Component
public class UserClient {
    private final WebClient.Builder webClientBuilder;

    public Mono<UserInfoRequestDto> getUser(String userId, String bearerToken) {
        return webClientBuilder.build()
                .get()
                .uri("http://auth/internal/users/{id}", userId) // 서비스 ID 기반
                .headers(h -> h.setBearerAuth(bearerToken))
                .retrieve()
                .bodyToMono(UserInfoRequestDto.class);
    }
}
