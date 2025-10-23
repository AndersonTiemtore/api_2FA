package com.api._FA.dto;

import lombok.Data;

@Data
public class AuthRequest {
    private String email;
    private String password;
    private String totpCode;
}