package com.portfoliopro.auth.service.token;

import java.security.SecureRandom;

import org.springframework.stereotype.Service;

import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.token.PasswordResetOtp;
import com.portfoliopro.auth.repository.PasswordResetRepository;

@Service
public class PasswordResetService extends TokenTemplate<PasswordResetOtp> {
    private final PasswordResetRepository otpRepository;
    private final static SecureRandom random = new SecureRandom();

    public PasswordResetService(PasswordResetRepository otpRepository) {
        super(otpRepository);
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

}
