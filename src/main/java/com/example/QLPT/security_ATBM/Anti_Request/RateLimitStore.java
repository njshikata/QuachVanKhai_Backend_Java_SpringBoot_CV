package com.example.QLPT.security_ATBM.Anti_Request;

public interface RateLimitStore {
    /**
     * @return 0 nếu hợp lệ, hoặc số giây cần chờ nếu vượt giới hạn.
     */
    long checkAndConsume(String key, int maxRequests, long windowSeconds);
}