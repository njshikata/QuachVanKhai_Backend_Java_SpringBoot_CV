package com.example.QLPT.security_ATBM.Anti_Request;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class AntiRequest extends OncePerRequestFilter {

    @Autowired
    private RateLimitStore rateLimitStore;

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    // =========================================================================
    // CẤU HÌNH LUẬT TẬP TRUNG - MUỐN CHẶN THÊM API CHỈ CẦN THÊM 1 DÒNG Ở ĐÂY
    // =========================================================================
    private static final List<RateLimitRule> RULES = List.of(
            new RateLimitRule("POST", "/api/auth/login", 5, 60),        // 5 lần / 1 phút
            new RateLimitRule("POST", "/api/auth/register", 3, 300)     // 3 lần / 5 phút
            // Ví dụ mở rộng sau này:
            // new RateLimitRule("GET",  "/api/pay/vietqr/**", 10, 60), // 10 lần / 1 phút
            // new RateLimitRule("*",    "/api/public/**", 60, 60)      // 60 lần / 1 phút
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Bỏ qua CORS preflight (OPTIONS) để không chặn Flutter Web
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        String method = request.getMethod();
        String path = request.getRequestURI();

        RateLimitRule matchedRule = findMatchingRule(method, path);
        if (matchedRule == null) {
            filterChain.doFilter(request, response);
            return;
        }

        String clientIp = getClientIp(request);
        // Key gắn theo IP + pattern của rule (tránh lách luật bằng cách đổi path variable)
        String key = clientIp + ":" + matchedRule.httpMethod() + ":" + matchedRule.pathPattern();

        long retryAfterSeconds = rateLimitStore.checkAndConsume(
                key,
                matchedRule.maxRequests(),
                matchedRule.windowSeconds()
        );

        if (retryAfterSeconds > 0) {
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType("text/plain; charset=UTF-8");
            response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
            response.getWriter().write("Bạn thao tác quá nhanh! Vui lòng thử lại sau " + retryAfterSeconds + " giây.");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private RateLimitRule findMatchingRule(String method, String path) {
        for (RateLimitRule rule : RULES) {
            boolean methodMatches = "*".equals(rule.httpMethod()) || rule.httpMethod().equalsIgnoreCase(method);
            if (methodMatches && pathMatcher.match(rule.pathPattern(), path)) {
                return rule;
            }
        }
        return null;
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}