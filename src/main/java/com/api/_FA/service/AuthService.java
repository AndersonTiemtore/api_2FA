package com.api._FA.service;

import com.api._FA.entity.User;
import com.api._FA.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TwoFactorService twoFactorService;
    
    public User register(String email, String password) {
        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("Email déjà utilisé");
        }
        
        User user = new User();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        
        return userRepository.save(user);
    }
    
    public User authenticate(String email, String password) {
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));
            
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Mot de passe incorrect");
        }
        
        return user;
    }
    
    public String enableTwoFactor(Long userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));
            
        String secret = twoFactorService.generateSecretKey();
        user.setTwoFactorSecret(secret);
        user.setTwoFactorEnabled(true);
        userRepository.save(user);
        
        return twoFactorService.generateQRCodeUrl(user.getEmail(), secret);
    }
    
    public boolean verifyTwoFactor(Long userId, int code) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));
            
        if (!user.isTwoFactorEnabled()) {
            return false;
        }
        
        boolean isValid = twoFactorService.verifyCode(user.getTwoFactorSecret(), code);
        if (isValid) {
            user.setVerified(true);
            userRepository.save(user);
        }
        
        return isValid;
    }
}