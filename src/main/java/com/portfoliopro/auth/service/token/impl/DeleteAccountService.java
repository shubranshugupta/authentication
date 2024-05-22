package com.portfoliopro.auth.service.token.impl;

import java.security.SecureRandom;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.portfoliopro.auth.dto.EmailDTO;
import com.portfoliopro.auth.dto.emaildtoimpl.TokenEmailDTO;
import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.token.impl.DeleteAccountOtp;
import com.portfoliopro.auth.event.DeleteAccountEvent;
import com.portfoliopro.auth.repository.DeleteAccountRepository;
import com.portfoliopro.auth.service.token.TokenTemplate;

@Service
public class DeleteAccountService extends TokenTemplate<DeleteAccountOtp> {
    private final DeleteAccountRepository otpRepository;
    private final static SecureRandom random = new SecureRandom();

    public DeleteAccountService(DeleteAccountRepository otpRepository, ApplicationEventPublisher eventPublisher) {
        super(otpRepository, eventPublisher);
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

    @Override
    protected ApplicationEvent getApplicationEvent(User user, EmailDTO tokenEmailDTO) {
        return new DeleteAccountEvent(user, tokenEmailDTO);
    }

    @Override
    protected EmailDTO getEmailDto(User user, DeleteAccountOtp newToken) {
        return TokenEmailDTO.builder()
                .email(user.getEmail())
                .firstName(StringUtils.capitalize(user.getFirstName()))
                .lastName(StringUtils.capitalize(user.getLastName()))
                .token(newToken.getToken())
                .baseUrl(getAppUrl())
                .build();
    }
}
