package com.example.QLPT.Enity;

import com.example.QLPT.Enity.Enum.Enum;
import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class User {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;
    @Column(nullable = false)
    private String password;
    @Convert(converter = com.example.QLPT.security_ATBM.AES_256_Data.AES_256_Data.class) // Mã hóa AES-256
    private String phoneNumber;
    @Convert(converter = com.example.QLPT.security_ATBM.AES_256_Data.AES_256_Data.class) // Mã hóa AES-256
    private String fullName;
    @Convert(converter = com.example.QLPT.security_ATBM.AES_256_Data.AES_256_Data.class) // Mã hóa AES-256
    private String identityNumber;
    private String avatarUrl;

    @Enumerated(EnumType.STRING)
    private Enum.Role role;

    @Enumerated(EnumType.STRING)
    private Enum.UserStatus status;
    // THÊM DÒNG NÀY ĐỂ LƯU TOKEN FIREBASE
    @Column(name = "fcm_token", columnDefinition = "TEXT")
    private String fcmToken;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private LocalDateTime deletedAt;
}
