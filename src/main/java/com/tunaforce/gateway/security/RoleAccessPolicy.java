package com.tunaforce.gateway.security;

/**
 * 역할별 허용 경로 정책을 담당하는 헬퍼 클래스
 * - URL 시작 경로 기반의 단순 접근 제어
 */
public final class RoleAccessPolicy {

    private RoleAccessPolicy() {
    }

    /**
     * 허용되면 태그 문자열을, 거부되면 null을 반환합니다.
     */
    public static String getAccessTag(String role, String rawPath) {
        String path = (rawPath == null) ? "/" : rawPath.toLowerCase();

        // 공통 허용: 로그인 사용자면 누구나 접근 가능 (역할 무관)
        if (startsWithAny(path, "/deliveries", "/delivery-agents", "/delivery-route-legs")) {
            return "ANY{deliveries,delivery-agents,delivery-route-legs}";
        }

        if (role == null || role.isBlank()) return null;
        String r = role.toUpperCase();

        // MASTER: 전체 허용
        switch (r) {
            case "MASTER" -> {
                return "MASTER-ALL";
            }
            // DELIVERY 허용: /hubs/**, /hub-routes/**, /orders/**, /messages/**
            case "DELIVERY" -> {
                if (startsWithAny(path, "/hubs", "/hub-routes", "/orders", "/messages",
                        "/deliveries", "/delivery-agents", "/delivery-route-legs"
                ))
                    return "DELIVERY{hubs,hub-routes,orders,messages}";
                return null;
            }
            // COMPANY 허용: /products/**, /companies/**, /orders/**, /messages/**
            case "COMPANY" -> {
                if (startsWithAny(path, "/products", "/companies", "/orders", "/messages"))
                    return "COMPANY{products,companies,orders}";
                return null;
            }
            // HUB 허용: /hubs/**, /hub-routes/**, /companies/**, /messages/**
            case "HUB" -> {
                if (startsWithAny(path, "/hubs", "/hub-routes", "/companies", "/messages"))
                    return "HUB{hubs,hub-routes,companies}";
                return null;
            }
        }
        return null; // 알 수 없는 역할
    }

    private static boolean startsWithAny(String path, String... prefixes) {
        for (String p : prefixes) {
            if (path.startsWith(p)) return true;
        }
        return false;
    }
}
