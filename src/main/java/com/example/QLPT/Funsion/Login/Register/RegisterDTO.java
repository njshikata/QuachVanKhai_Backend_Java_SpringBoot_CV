package com.example.QLPT.Funsion.Login.Register;

import jakarta.validation.constraints.*;
import lombok.Data;

@Data
public class RegisterDTO {

    @NotBlank(message = "Email không được để trống")
    @Email(message = "Định dạng email không hợp lệ")
    @Size(max = 255, message = "Email không vượt quá 255 ký tự")
    private String email;

    // Giới hạn max = 72 rất chuẩn vì BCrypt chỉ băm tối đa 72 bytes đầu tiên
    @NotBlank(message = "Mật khẩu không được để trống")
    @Size(min = 6, max = 72, message = "Mật khẩu phải từ 6 đến 72 ký tự")
    private String password;

    @NotBlank(message = "Họ tên không được để trống")
    @Size(max = 100, message = "Họ tên không vượt quá 100 ký tự")
    // Chỉ cho phép chữ cái (bao gồm tiếng Việt có dấu) và khoảng trắng, chặn mọi ký tự đặc biệt/XSS
    @Pattern(regexp = "^[\\p{L}\\s]+$", message = "Họ tên chỉ được chứa chữ cái và khoảng trắng")
    private String fullName;

    @NotBlank(message = "Số điện thoại không được để trống")
    // Chuẩn số điện thoại Việt Nam (10 số, bắt đầu bằng số 0)
    @Pattern(regexp = "^0\\d{9}$", message = "Số điện thoại phải gồm 10 chữ số và bắt đầu bằng số 0")
    private String phoneNumber;

    @NotBlank(message = "Số CCCD/CMND không được để trống")
    // Chỉ cho phép nhập 9 số (CMND cũ) hoặc 12 số (CCCD mới)
    @Pattern(regexp = "^(\\d{9}|\\d{12})$", message = "Số CCCD/CMND phải gồm 9 hoặc 12 chữ số")
    private String identityNumber;
}