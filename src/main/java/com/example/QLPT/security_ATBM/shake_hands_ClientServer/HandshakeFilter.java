package com.example.QLPT.security_ATBM.shake_hands_ClientServer;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class HandshakeFilter extends OncePerRequestFilter {

    @Value("${app.security.rsa-private-key}")
    private String rsaPrivateKey;

    private static final long MAX_TIME_DIFF_MS = 60000;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        if (path.startsWith("/images/") || path.startsWith("/uploads/") || path.startsWith("/api/pay/sepay-webhook")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Chỉ nhận 1 Header duy nhất đã bị bọc bằng RSA Public Key từ Flutter
        String encryptedPayload = request.getHeader("X-App-RSA-Payload");

        if (encryptedPayload == null || encryptedPayload.isEmpty()) {
            rejectRequest(response, "Thiếu Handshake Payload.");
            return;
        }

        try {
            // Dùng Private Key để mở khóa lấy Timestamp
            String decryptedTimestamp = RSAUtils.decryptTimestamp(encryptedPayload, rsaPrivateKey);
            long clientTime = Long.parseLong(decryptedTimestamp);
            long serverTime = System.currentTimeMillis();

            // Check chống replay attack (Spam lại request cũ)
            if (Math.abs(serverTime - clientTime) > MAX_TIME_DIFF_MS) {
                rejectRequest(response, "Request quá hạn. Bị từ chối.");
                return;
            }

        } catch (Exception e) {
            // Lỗi giải mã => Request giả mạo hoặc dùng sai Public Key
            rejectRequest(response, "Dữ liệu Handshake không hợp lệ.");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void rejectRequest(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write("{\"error\": \"" + message + "\"}");
    }
}