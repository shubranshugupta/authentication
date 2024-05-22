package com.portfoliopro.auth.service.token.impl;

import java.util.UUID;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.portfoliopro.auth.dto.EmailDTO;
import com.portfoliopro.auth.dto.emaildtoimpl.TokenEmailDTO;
import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.token.impl.VerificationToken;
import com.portfoliopro.auth.event.RegistrationCompletionEvent;
import com.portfoliopro.auth.repository.VerificationTokenRepository;
import com.portfoliopro.auth.service.token.TokenTemplate;

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
    protected ApplicationEvent getApplicationEvent(User user, EmailDTO tokenEmailDTO) {
        return new RegistrationCompletionEvent(user, tokenEmailDTO);
    }

    @Override
    protected EmailDTO getEmailDto(User user, VerificationToken newToken) {
        String appUrl = getAppUrl() + "/auth/verifyEmail?token=" + newToken.getToken()
                + "&email=" + user.getEmail();

        return TokenEmailDTO.builder()
                .email(user.getEmail())
                .firstName(StringUtils.capitalize(user.getFirstName()))
                .lastName(StringUtils.capitalize(user.getLastName()))
                .token(appUrl)
                .baseUrl(getAppUrl())
                .build();
    }

}
