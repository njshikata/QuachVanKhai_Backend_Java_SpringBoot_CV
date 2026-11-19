package com.example.QLPT.security_ATBM.Anti_Request;

import org.springframework.stereotype.Component;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class InMemoryRateLimitStore implements RateLimitStore {

    private static final int MAX_TRACKED_KEYS = 10_000;
    private static final long CLEANUP_MAX_WINDOW_MS = 30 * 60_000L; // 30 phút

    private final Map<String, Deque<Long>> requestLogs = new ConcurrentHashMap<>();

    @Override
    public long checkAndConsume(String key, int maxRequests, long windowSeconds) {
        long now = System.currentTimeMillis();
        long windowMs = windowSeconds * 1000L;

        if (requestLogs.size() > MAX_TRACKED_KEYS) {
            cleanupExpired(now);
        }

        Deque<Long> timestamps = requestLogs.computeIfAbsent(key, k -> new ArrayDeque<>());

        synchronized (timestamps) {
            while (!timestamps.isEmpty() && (now - timestamps.peekFirst()) >= windowMs) {
                timestamps.pollFirst();
            }

            if (timestamps.size() >= maxRequests) {
                long waitMs = windowMs - (now - timestamps.peekFirst());
                return Math.max(1, (waitMs + 999) / 1000);
            }

            timestamps.addLast(now);
            return 0;
        }
    }

    private void cleanupExpired(long now) {
        requestLogs.entrySet().removeIf(entry -> {
            Deque<Long> q = entry.getValue();
            synchronized (q) {
                while (!q.isEmpty() && (now - q.peekFirst()) >= CLEANUP_MAX_WINDOW_MS) {
                    q.pollFirst();
                }
                return q.isEmpty();
            }
        });
    }
}