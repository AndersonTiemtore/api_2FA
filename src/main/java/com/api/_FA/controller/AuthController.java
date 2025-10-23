package com.api._FA.controller;

import com.api._FA.dto.AuthRequest;
import com.api._FA.dto.AuthResponse;
import com.api._FA.entity.User;
import com.api._FA.service.AuthService;
import com.api._FA.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    
    private final AuthService authService;
    private final JwtService jwtService;
    
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody AuthRequest request) {
        authService.register(request.getEmail(), request.getPassword());
        return ResponseEntity.ok("Utilisateur créé avec succès");
    }
    
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest request) {
        User user = authService.authenticate(request.getEmail(), request.getPassword());
        
        if (user.isTwoFactorEnabled()) {
            if (request.getTotpCode() == null) {
                return ResponseEntity.ok(new AuthResponse(null, true, null));
            }
            
            boolean isValidCode = authService.verifyTwoFactor(user.getId(), 
                Integer.parseInt(request.getTotpCode()));
            
            if (!isValidCode) {
                return ResponseEntity.badRequest().body(
                    new AuthResponse(null, true, "Code 2FA invalide"));
            }
        }
        
        String token = jwtService.generateToken(user.getEmail(), user.getId());
        return ResponseEntity.ok(new AuthResponse(token, false, null));
    }
    
    @PostMapping("/enable-2fa")
    public ResponseEntity<AuthResponse> enableTwoFactor(@RequestHeader("Authorization") String token) {
        try {
            String jwtToken = token.substring(7); // Enlever "Bearer "
            String email = jwtService.extractEmail(jwtToken);
            Long userId = jwtService.extractUserId(jwtToken);
            
            String qrUrl = authService.enableTwoFactor(userId);
            
            return ResponseEntity.ok(new AuthResponse(null, false, qrUrl));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new AuthResponse(null, false, "Erreur: " + e.getMessage()));
        }
    }
    
    @PostMapping("/verify-2fa")
    public ResponseEntity<String> verifyTwoFactor(@RequestParam Long userId, 
                                                 @RequestParam int code) {
        boolean isValid = authService.verifyTwoFactor(userId, code);
        
        if (isValid) {
            return ResponseEntity.ok("2FA activé avec succès");
        }
        
        return ResponseEntity.badRequest().body("Code invalide");
    }
}