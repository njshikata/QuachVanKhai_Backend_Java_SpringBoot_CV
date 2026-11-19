package com.example.QLPT.Funsion.Login.Login;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class LoginDTO {

    @NotBlank(message = "Email không được để trống")
    @Email(message = "Định dạng email không hợp lệ")
    @Size(max = 255, message = "Email không vượt quá 255 ký tự")
    private String email;

    @NotBlank(message = "Mật khẩu không được để trống")
    @Size(min = 6, max = 72, message = "Mật khẩu phải từ 6 đến 72 ký tự")
    private String password;

    // FCM tokens are stored as TEXT; they can exceed 255 characters.
    // Chỉ cho phép các ký tự chuẩn của Firebase Token, chặn hoàn toàn thẻ <script> hay SQL/HTML injection
    @Size(max = 4096, message = "FCM Token quá dài")
    @Pattern(regexp = "^[a-zA-Z0-9\\-_:]*$", message = "FCM Token chứa ký tự không hợp lệ")
    private String fcmToken;
}