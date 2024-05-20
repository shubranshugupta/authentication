package com.portfoliopro.auth.service;

import org.springframework.stereotype.Service;

import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.token.PasswordResetOtp;
import com.portfoliopro.auth.entities.token.Token;
import com.portfoliopro.auth.entities.token.VerificationToken;
import com.portfoliopro.auth.service.token.TokenTemplate;
import com.portfoliopro.auth.service.token.TokenType;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class TokenServiceFacade {
    private final TokenTemplate<VerificationToken> verificationTokenService;
    private final TokenTemplate<PasswordResetOtp> passwordResetService;

    public Token createToken(User user, TokenType tokenType) {
        switch (tokenType) {
            case VERFICATION_TOKEN:
                return verificationTokenService.createToken(user);
            case RESET_PASSWORD_TOKEN:
                return passwordResetService.createToken(user);
            default:
                throw new IllegalArgumentException("Invalid token type");
        }
    }

    public boolean verifyToken(User user, String token, TokenType tokenType) {
        switch (tokenType) {
            case VERFICATION_TOKEN:
                return verificationTokenService.verifyToken(user, token);
            case RESET_PASSWORD_TOKEN:
                return passwordResetService.verifyToken(user, token);
            default:
                throw new IllegalArgumentException("Invalid token type");
        }
    }
}
