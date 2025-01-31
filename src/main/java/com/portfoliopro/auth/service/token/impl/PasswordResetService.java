package com.portfoliopro.auth.service.token.impl;

import java.security.SecureRandom;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.portfoliopro.auth.dto.EmailDTO;
import com.portfoliopro.auth.dto.emaildtoimpl.TokenEmailDTO;
import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.token.impl.PasswordResetOtp;
import com.portfoliopro.auth.event.PasswordResetEvent;
import com.portfoliopro.auth.repository.PasswordResetRepository;
import com.portfoliopro.auth.service.token.TokenTemplate;

@Service
public class PasswordResetService extends TokenTemplate<PasswordResetOtp> {
    private final PasswordResetRepository otpRepository;
    private final static SecureRandom random = new SecureRandom();

    public PasswordResetService(PasswordResetRepository otpRepository, ApplicationEventPublisher eventPublisher) {
        super(otpRepository, eventPublisher);
        this.otpRepository = otpRepository;
    }

    @Override
    protected PasswordResetOtp createNewToken() {
        return new PasswordResetOtp();
    }

    @Override
    protected PasswordResetOtp getTokenFromUser(User user) {
        return otpRepository.findByUser(user).orElse(null);
    }

    @Override
    protected String generateRandomTokenID() {
        return String.valueOf(random.nextLong(100_000, 999_999));
    }

    @Override
    protected void deleteToken(PasswordResetOtp origToken) {
        otpRepository.delete(origToken);
    }

    @Override
    protected ApplicationEvent getApplicationEvent(User user, EmailDTO tokenEmailDTO) {
        return new PasswordResetEvent(user, tokenEmailDTO);
    }

    @Override
    protected EmailDTO getEmailDto(User user, PasswordResetOtp newToken) {
        return TokenEmailDTO.builder()
                .email(user.getEmail())
                .firstName(StringUtils.capitalize(user.getFirstName()))
                .lastName(StringUtils.capitalize(user.getLastName()))
                .token(newToken.getToken())
                .baseUrl(getAppUrl())
                .build();
    }

}
