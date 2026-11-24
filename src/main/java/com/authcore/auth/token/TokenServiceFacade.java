package com.authcore.auth.token;

import org.springframework.stereotype.Service;

import com.authcore.auth.user.User;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class TokenServiceFacade {
    private final TokenTemplate<VerificationToken> verificationTokenService;
    private final TokenTemplate<PasswordResetOtp> passwordResetService;
    private final TokenTemplate<DeleteAccountOtp> deleteAccountService;

    private Token createToken(User user, TokenType tokenType) {
        switch (tokenType) {
            case VERIFICATION_TOKEN:
                return verificationTokenService.createToken(user);
            case RESET_PASSWORD_TOKEN:
                return passwordResetService.createToken(user);
            case DELETE_ACCOUNT_TOKEN:
                return deleteAccountService.createToken(user);
            default:
                throw new IllegalArgumentException("Invalid token type");
        }
    }

    private void sendMail(User user, Token newToken, TokenType tokenType) {
        switch (tokenType) {
            case VERIFICATION_TOKEN:
                verificationTokenService.publishEmailEvent(user, (VerificationToken) newToken);
                break;
            case RESET_PASSWORD_TOKEN:
                passwordResetService.publishEmailEvent(user, (PasswordResetOtp) newToken);
                break;
            case DELETE_ACCOUNT_TOKEN:
                deleteAccountService.publishEmailEvent(user, (DeleteAccountOtp) newToken);
                break;
            default:
                throw new IllegalArgumentException("Invalid token type");
        }
    }

    public boolean createTokenAndSendMail(User user, TokenType tokenType) {
        switch (tokenType) {
            case VERIFICATION_TOKEN:
            case RESET_PASSWORD_TOKEN:
            case DELETE_ACCOUNT_TOKEN:
                Token newToken = createToken(user, tokenType);
                sendMail(user, newToken, tokenType);
                return true;
            default:
                throw new IllegalArgumentException("Invalid token type");
        }
    }

    public boolean verifyToken(User user, String token, TokenType tokenType) {
        switch (tokenType) {
            case VERIFICATION_TOKEN:
                return verificationTokenService.verifyToken(user, token);
            case RESET_PASSWORD_TOKEN:
                return passwordResetService.verifyToken(user, token);
            case DELETE_ACCOUNT_TOKEN:
                return deleteAccountService.verifyToken(user, token);
            default:
                throw new IllegalArgumentException("Invalid token type");
        }
    }
}
