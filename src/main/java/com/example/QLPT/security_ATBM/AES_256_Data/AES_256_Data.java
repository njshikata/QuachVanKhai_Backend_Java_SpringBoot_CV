package com.example.QLPT.security_ATBM.AES_256_Data;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * MÃ HÓA DỮ LIỆU NGƯỜI DÙNG BẰNG AES-256 (đối xứng: cùng 1 khóa để mã hóa và giải mã)
 *
 * Class này làm 2 việc:
 *  1. Là "Converter" của JPA: gắn @Convert lên field nào trong Entity thì
 *     - Khi LƯU xuống DB  -> tự động gọi convertToDatabaseColumn() -> MÃ HÓA
 *     - Khi ĐỌC từ DB lên -> tự động gọi convertToEntityAttribute() -> GIẢI MÃ
 *     => Các Service/Controller KHÔNG phải sửa gì, vẫn get/set chữ bình thường.
 *  2. Là "ApplicationRunner": mỗi lần khởi động server sẽ quét bảng users,
 *     dòng nào còn chữ thường (data cũ chưa mã hóa) thì mã hóa luôn.
 *
 * Thuật toán: AES-256-GCM
 *  - Khóa 256 bit (32 byte), lấy từ application.properties (app.security.aes-256-key)
 *  - IV 12 byte NGẪU NHIÊN mỗi lần mã hóa -> cùng 1 chữ mã hóa 2 lần ra 2 kết quả khác nhau
 *  - GCM có thêm "tag" 16 byte để phát hiện dữ liệu trong DB bị sửa trái phép
 *
 * Định dạng lưu trong DB:  Base64( IV(12 byte) + CipherText + Tag(16 byte) )
 *  - KHÔNG gắn chữ gì để lộ thuật toán, nhìn vào DB chỉ thấy chuỗi ngẫu nhiên.
 *  - Phân biệt data ĐÃ mã hóa và data CŨ: thử giải mã bằng khóa của mình (isEncrypted).
 *    Nhờ Tag của GCM, chỉ chuỗi do chính khóa này mã hóa mới giải mã được,
 *    chữ thường của data cũ chắc chắn giải mã thất bại -> biết là chưa mã hóa.
 */
@Component
@Converter
public class AES_256_Data implements AttributeConverter<String, String>, ApplicationRunner {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_LENGTH = 12;                   // 12 byte = chuẩn cho GCM
    private static final int TAG_LENGTH_BIT = 128;             // Tag xác thực 16 byte

    // Các cột của bảng users cần mã hóa (phải khớp với các field gắn @Convert trong User.java)
    private static final String[] USER_COLUMNS = {"full_name", "phone_number", "identity_number"};

    private static SecretKeySpec secretKey;                    // static để mọi nơi dùng chung 1 khóa
    private static final SecureRandom RANDOM = new SecureRandom();

    @Autowired
    private JdbcTemplate jdbcTemplate;

    // ===================== NẠP KHÓA AES-256 =====================
    @Value("${app.security.aes-256-key}")
    public void setKey(String base64Key) {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key.trim());
        if (keyBytes.length != 32) {
            throw new IllegalStateException("Khóa AES-256 phải đúng 32 byte, hiện tại là " + keyBytes.length + " byte");
        }
        secretKey = new SecretKeySpec(keyBytes, "AES");
    }

    // ===================== MÃ HÓA =====================
    public static String encrypt(String plainText) {
        if (plainText == null || isEncrypted(plainText)) {
            return plainText; // null hoặc đã mã hóa rồi thì không mã hóa lần 2
        }
        try {
            // 1. Sinh IV ngẫu nhiên
            byte[] iv = new byte[IV_LENGTH];
            RANDOM.nextBytes(iv);

            // 2. Mã hóa bằng khóa + IV
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            // 3. Ghép IV + CipherText rồi chuyển Base64 để lưu dạng chữ
            byte[] combined = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(cipherText, 0, combined, iv.length, cipherText.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new IllegalStateException("Lỗi mã hóa AES-256", e);
        }
    }

    // ===================== GIẢI MÃ =====================
    public static String decrypt(String dbData) {
        try {
            return tryDecrypt(dbData);
        } catch (Exception e) {
            return dbData; // Data cũ chưa mã hóa -> trả nguyên văn, không bị lỗi
        }
    }

    // Kiểm tra 1 chuỗi đã được mã hóa bằng khóa của mình chưa (giải mã được = đã mã hóa)
    public static boolean isEncrypted(String data) {
        try {
            tryDecrypt(data);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // Giải mã thật sự, sai khóa / không phải bản mã -> ném Exception
    private static String tryDecrypt(String dbData) throws Exception {
        if (dbData == null) {
            return null;
        }
        // 1. Giải Base64
        byte[] combined = Base64.getDecoder().decode(dbData);
        if (combined.length < IV_LENGTH + TAG_LENGTH_BIT / 8) {
            throw new IllegalArgumentException("Quá ngắn, không phải bản mã");
        }

        // 2. Tách IV (12 byte đầu) và CipherText (phần còn lại)
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(combined, 0, iv, 0, IV_LENGTH);

        // 3. Giải mã bằng cùng khóa + IV (GCM tự kiểm tra Tag, sai là ném Exception)
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] plain = cipher.doFinal(combined, IV_LENGTH, combined.length - IV_LENGTH);

        return new String(plain, StandardCharsets.UTF_8);
    }

    // ===================== JPA TỰ GỌI =====================
    @Override
    public String convertToDatabaseColumn(String attribute) { // Java -> DB
        return encrypt(attribute);
    }

    @Override
    public String convertToEntityAttribute(String dbData) {   // DB -> Java
        return decrypt(dbData);
    }

    // ===================== MÃ HÓA DATA CŨ KHI KHỞI ĐỘNG =====================
    @Override
    public void run(ApplicationArguments args) {
        List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                "SELECT id, " + String.join(", ", USER_COLUMNS) + " FROM users");

        int count = 0;
        for (Map<String, Object> row : rows) {
            for (String column : USER_COLUMNS) {
                String value = (String) row.get(column);
                if (value != null && !isEncrypted(value)) { // chưa mã hóa
                    jdbcTemplate.update("UPDATE users SET " + column + " = ? WHERE id = ?",
                            encrypt(value), row.get("id"));
                    count++;
                }
            }
        }
        System.out.println("[AES-256] Đã mã hóa " + count + " ô dữ liệu cũ trong bảng users.");
    }
}
