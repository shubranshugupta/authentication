package com.portfoliopro.auth.service.token;

import java.security.SecureRandom;

import org.springframework.stereotype.Service;

import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.token.Otp;
import com.portfoliopro.auth.repository.OtpTokenRepository;

@Service
public class PasswordResetService extends TokenTemplate<Otp> {
    private final OtpTokenRepository otpRepository;
    private final static SecureRandom random = new SecureRandom();

    public PasswordResetService(OtpTokenRepository otpRepository) {
        super(otpRepository);
        this.otpRepository = otpRepository;
    }

    @Override
    protected Otp createNewToken() {
        return new Otp();
    }

    @Override
    protected Otp getTokenFromUser(User user) {
        return otpRepository.findByUser(user).orElse(null);
    }

    @Override
    protected String generateRandomTokenID() {
        return String.valueOf(random.nextLong(100_000, 999_999));
    }

}
