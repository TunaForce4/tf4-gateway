package com.tunaforce.gateway.dto.request;

import java.time.LocalDateTime;
import java.util.UUID;

public record UserInfoRequestDto(
        UUID userId,
        String userLoginId,
        String username,
        String role,
        String slackId,
        String tel,
        LocalDateTime deletedAt,
        UUID deletedBy
) {
}
