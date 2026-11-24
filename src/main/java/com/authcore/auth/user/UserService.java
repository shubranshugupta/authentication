package com.authcore.auth.user;

import org.jspecify.annotations.Nullable;
import org.springframework.security.crypto.password.PasswordEncoder;
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
    private final PasswordEncoder passwordEncoder;

    public UserResponse getProfile(Integer userId) {
        User user = getUser(userId);
        return UserResponse.builder()
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .build();
    }

    /** Null means: keep it. An empty last name removes it. */
    public void updateProfile(Integer userId, @Nullable String firstName, @Nullable String lastName) {
        User user = getUser(userId);
        if (firstName != null)
            user.setFirstName(firstName);
        if (lastName != null)
            user.setLastName(lastName.isBlank() ? null : lastName);
        userRepository.save(user);
    }

    public void requestDeletion(Integer userId) {
        if (!tokens.issue(getUser(userId).getId(), TokenPurpose.ACCOUNT_DELETION))
            throw new TokenAlreadyExistsException("A code was sent less than a minute ago. Check your inbox, or try again in a minute.");
    }

    /**
     * Deletes the account, and with it every token. Needs the password too (H8): whoever
     * got hold of a session and the inbox must not be able to delete the account. A wrong
     * password uses up one of the code's attempts, so it can't be guessed here either.
     */
    public void confirmDeletion(Integer userId, String code, String password) {
        boolean deleted = transaction.run(() -> tokens
                .consumeCode(userId, code, TokenPurpose.ACCOUNT_DELETION,
                        user -> passwordEncoder.matches(password, user.getPassword()))
                .map(user -> {
                    userRepository.delete(user);
                    return true;
                }).orElse(false));
        if (!deleted)
            throw new InvalidCodeException("The code or the password is wrong, or the code has expired.");
    }

    private User getUser(Integer userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId));
    }
}
