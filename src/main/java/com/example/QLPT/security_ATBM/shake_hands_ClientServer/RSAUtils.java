package com.example.QLPT.security_ATBM.shake_hands_ClientServer;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class RSAUtils {
    // Hàm giải mã Payload từ Flutter gửi lên
    public static String decryptTimestamp(String encryptedBase64, String privateKeyStr) throws Exception {
        // 1. Xóa bỏ các ký tự thừa (nếu có copy nhầm)
        privateKeyStr = privateKeyStr.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        // 2. Nạp Private Key
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyStr);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(spec);

        // 3. Giải mã
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedBase64));

        return new String(decryptedBytes);
    }
}