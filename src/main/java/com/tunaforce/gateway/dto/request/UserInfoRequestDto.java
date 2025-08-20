package com.tunaforce.gateway.dto.request;

import java.util.UUID;

public record UserInfoRequestDto(
        UUID userId,
        String userLoginId,
        String username,
        String role,
        String slackId,
        String tel
) {
}
