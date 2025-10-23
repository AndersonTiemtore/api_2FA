package com.api._FA.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthResponse {
    private String token;
    private boolean requiresTwoFactor;
    private String qrCodeUrl;
}