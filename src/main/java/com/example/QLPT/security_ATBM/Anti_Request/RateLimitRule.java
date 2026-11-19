package com.example.QLPT.security_ATBM.Anti_Request;

public record RateLimitRule(
        String httpMethod,   // "POST", "GET", hoặc "*" (áp dụng mọi method)
        String pathPattern,  // Hỗ trợ Ant-style: "/api/auth/login", "/api/pay/vietqr/**"
        int maxRequests,     // Số request tối đa
        long windowSeconds   // Trong khoảng thời gian (giây)
) {}