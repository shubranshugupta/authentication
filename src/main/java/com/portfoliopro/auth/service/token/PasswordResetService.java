package com.portfoliopro.auth.service.token;

import java.security.SecureRandom;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import com.portfoliopro.auth.dto.TokenEmailDTO;
import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.token.PasswordResetOtp;
import com.portfoliopro.auth.event.PasswordResetEvent;
import com.portfoliopro.auth.repository.PasswordResetRepository;

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
    protected ApplicationEvent getApplicationEvent(User user, TokenEmailDTO tokenEmailDTO) {
        return new PasswordResetEvent(user, tokenEmailDTO);
    }

    @Override
    protected TokenEmailDTO getTokenEmailDto(User user, PasswordResetOtp newToken) {
        return TokenEmailDTO.builder()
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .token(newToken.getToken())
                .baseUrl(getAppUrl())
                .build();
    }

}
