package com.portfoliopro.auth.service.token;

import java.security.SecureRandom;

import org.springframework.stereotype.Service;

import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.token.DeleteAccountOtp;
import com.portfoliopro.auth.repository.DeleteAccountRepository;

@Service
public class DeleteAccountService extends TokenTemplate<DeleteAccountOtp> {
    private final DeleteAccountRepository otpRepository;
    private final static SecureRandom random = new SecureRandom();

    public DeleteAccountService(DeleteAccountRepository otpRepository) {
        super(otpRepository);
        this.otpRepository = otpRepository;
    }

    @Override
    protected DeleteAccountOtp createNewToken() {
        return new DeleteAccountOtp();
    }

    @Override
    protected DeleteAccountOtp getTokenFromUser(User user) {
        return otpRepository.findByUser(user).orElse(null);
    }

    @Override
    protected String generateRandomTokenID() {
        return String.valueOf(random.nextLong(100_000, 999_999));
    }

    @Override
    protected void deleteToken(DeleteAccountOtp origToken) {
    }
}
