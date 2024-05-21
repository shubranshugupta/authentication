package com.portfoliopro.auth.service.token;

import java.util.UUID;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import com.portfoliopro.auth.dto.TokenEmailDTO;
import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.token.VerificationToken;
import com.portfoliopro.auth.event.RegistrationCompletionEvent;
import com.portfoliopro.auth.repository.VerificationTokenRepository;

@Service
public class VerificationTokenService extends TokenTemplate<VerificationToken> {
    private final VerificationTokenRepository verificationTokenRepository;

    public VerificationTokenService(VerificationTokenRepository verificationTokenRepository,
            ApplicationEventPublisher eventPublisher) {
        super(verificationTokenRepository, eventPublisher);
        this.verificationTokenRepository = verificationTokenRepository;
    }

    @Override
    protected VerificationToken createNewToken() {
        return new VerificationToken();
    }

    @Override
    protected VerificationToken getTokenFromUser(User user) {
        return verificationTokenRepository.findByUser(user).orElse(null);
    }

    @Override
    protected String generateRandomTokenID() {
        return UUID.randomUUID().toString();
    }

    @Override
    protected void deleteToken(VerificationToken origToken) {
        verificationTokenRepository.delete(origToken);
    }

    @Override
    protected ApplicationEvent getApplicationEvent(User user, TokenEmailDTO tokenEmailDTO) {
        return new RegistrationCompletionEvent(user, tokenEmailDTO);
    }

    @Override
    protected TokenEmailDTO getTokenEmailDto(User user, VerificationToken newToken) {
        String appUrl = getAppUrl() + "/auth/verifyEmail?token=" + newToken.getToken()
                + "&email=" + user.getEmail();

        return TokenEmailDTO.builder()
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .token(appUrl)
                .baseUrl(getAppUrl())
                .build();
    }

}
