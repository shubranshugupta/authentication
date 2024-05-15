package com.portfoliopro.auth.service;

import java.time.Instant;
import java.util.Random;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.portfoliopro.auth.entities.Otp;
import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.exception.TokenExpireException;
import com.portfoliopro.auth.exception.InvalidTokenException;
import com.portfoliopro.auth.repository.OtpRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class PasswordResetService {
    private final OtpRepository otpRepository;

    @Value("${auth.token.otp-expiration}")
    private long expireTime;

    private static final Random random = new Random();

    public Otp createOtp(User user) {
        Otp otp = user.getOtp();

        if (otp != null && otp.getExpiryDate().isAfter(Instant.now()))
            return otp;

        if (otp != null)
            otpRepository.delete(otp);

        otp = Otp.builder()
                .user(user)
                .otp(otpGenerator())
                .expiryDate(Instant.now().plusMillis(expireTime))
                .build();

        otpRepository.save(otp);

        return otp;
    }

    public boolean verifyOtp(User user, long otpRequest) {
        Otp otp = user.getOtp();

        if (otp == null || otp.getOtp() != otpRequest) {
            throw new InvalidTokenException(otpRequest + " OTP is inavlid", new Throwable("Invalid OTP"));
        }

        if (otp.getExpiryDate().isBefore(Instant.now())) {
            otpRepository.delete(otp);
            throw new TokenExpireException(otpRequest + " OTP expired", new Throwable("OTP expired"));
        }

        otpRepository.delete(otp);
        return true;
    }

    private long otpGenerator() {
        return random.nextLong(100_000, 999_999);
    }
}
