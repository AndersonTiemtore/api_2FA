package com.api._FA.service;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import org.springframework.stereotype.Service;

@Service
public class TwoFactorService {
    
    private final GoogleAuthenticator gAuth = new GoogleAuthenticator();
    
    public String generateSecretKey() {
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        return key.getKey();
    }
    
    public String generateQRCodeUrl(String email, String secret) {
        // Format manuel de l'URL TOTP
        return String.format(
            "otpauth://totp/%s:%s?secret=%s&issuer=%s",
            "SecureAuth", email, secret, "SecureAuth"
        );
    }
    
    public boolean verifyCode(String secret, int code) {
        return gAuth.authorize(secret, code);
    }
}