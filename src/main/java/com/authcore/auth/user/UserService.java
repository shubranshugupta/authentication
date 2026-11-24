package com.authcore.auth.user;

import org.springframework.stereotype.Service;

import com.authcore.auth.common.RetryingTransaction;
import com.authcore.auth.token.InvalidCodeException;
import com.authcore.auth.token.OneTimeTokenService;
import com.authcore.auth.token.TokenAlreadyExistsException;
import com.authcore.auth.token.TokenPurpose;

import lombok.RequiredArgsConstructor;

/** What a logged-in user can do with their own account. Knows nothing about HTTP (A5). */
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final OneTimeTokenService tokens;
    private final RetryingTransaction transaction;

    public UserResponse getProfile(Integer userId) {
        User user = getUser(userId);
        return UserResponse.builder()
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .build();
    }

    public void updateProfile(Integer userId, String firstName, String lastName) {
        User user = getUser(userId);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        userRepository.save(user);
    }

    public void requestDeletion(Integer userId) {
        if (!tokens.issue(getUser(userId).getId(), TokenPurpose.ACCOUNT_DELETION))
            throw new TokenAlreadyExistsException("A code was sent less than a minute ago. Check your inbox, or try again in a minute.");
    }

    public void confirmDeletion(Integer userId, String code) {
        boolean deleted = transaction.run(() -> tokens
                .consumeCode(userId, code, TokenPurpose.ACCOUNT_DELETION, user -> true)
                .map(user -> {
                    userRepository.delete(user);
                    return true;
                }).orElse(false));
        if (!deleted)
            throw new InvalidCodeException("The code is invalid or has expired.");
    }

    private User getUser(Integer userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId));
    }
}
