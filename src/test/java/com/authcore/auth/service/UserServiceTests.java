package com.authcore.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.authcore.auth.entities.Role;
import com.authcore.auth.entities.User;
import com.authcore.auth.exception.InvalidTokenException;
import com.authcore.auth.repository.UserRepository;
import com.authcore.auth.service.token.TokenType;

/** A5: the service takes a user id instead of a raw "Bearer ..." header. */
@ExtendWith(MockitoExtension.class)
class UserServiceTests {
    @Mock
    private UserRepository userRepository;
    @Mock
    private TokenServiceFacade tokenService;
    @InjectMocks
    private UserService userService;

    private final User user = User.builder().id(7).email("jane@example.com").firstName("jane").lastName("doe")
            .password("hash").role(Role.USER).enabled(true).build();

    @Test
    void updateProfileChangesOnlyTheName() {
        when(userRepository.findById(7)).thenReturn(Optional.of(user));

        userService.updateProfile(7, "janet", null);

        verify(userRepository).save(user);
        assertThat(user.getFirstName()).isEqualTo("janet");
        assertThat(user.getLastName()).isNull();
        assertThat(user.getEmail()).isEqualTo("jane@example.com");
        assertThat(user.getPassword()).isEqualTo("hash");
    }

    @Test
    void confirmDeletionDeletesTheUserOnlyAfterTheCodeMatched() {
        when(userRepository.findById(7)).thenReturn(Optional.of(user));
        doThrow(new InvalidTokenException("wrong")).when(tokenService)
                .verifyToken(user, "111111", TokenType.DELETE_ACCOUNT_TOKEN);

        assertThatThrownBy(() -> userService.confirmDeletion(7, "111111")).isInstanceOf(InvalidTokenException.class);
        verify(userRepository, never()).delete(any());

        userService.confirmDeletion(7, "222222");
        verify(userRepository).delete(user);
    }
}
