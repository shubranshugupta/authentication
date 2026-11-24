package com.authcore.auth.service;

import org.springframework.stereotype.Service;

import com.authcore.auth.exception.UserNotFoundException;
import com.authcore.auth.dto.response.UserResponse;
import com.authcore.auth.entities.User;
import com.authcore.auth.repository.UserRepository;
import com.authcore.auth.service.token.TokenType;

import lombok.RequiredArgsConstructor;

/** What a logged-in user can do with their own account. Knows nothing about HTTP (A5). */
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final TokenServiceFacade tokenService;

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
        tokenService.createTokenAndSendMail(getUser(userId), TokenType.DELETE_ACCOUNT_TOKEN);
    }

    public void confirmDeletion(Integer userId, String otp) {
        User user = getUser(userId);
        tokenService.verifyToken(user, otp, TokenType.DELETE_ACCOUNT_TOKEN);
        userRepository.delete(user);
    }

    private User getUser(Integer userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId));
    }
}
