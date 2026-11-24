package com.authcore.auth.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.support.TransactionOperations;

import com.authcore.auth.common.RetryingTransaction;
import com.authcore.auth.token.InvalidCodeException;
import com.authcore.auth.token.OneTimeTokenService;
import com.authcore.auth.token.TokenAlreadyExistsException;
import com.authcore.auth.token.TokenPurpose;

/** A5: the service takes a user id instead of a raw "Bearer ..." header. */
@ExtendWith(MockitoExtension.class)
class UserServiceTests {
    @Mock
    private UserRepository userRepository;
    @Mock
    private OneTimeTokenService tokens;

    private UserService userService;

    @BeforeEach
    void createService() {
        userService = new UserService(userRepository, tokens,
                new RetryingTransaction(TransactionOperations.withoutTransaction()));
    }

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
        when(tokens.consumeCode(eq(7), eq("11111111"), eq(TokenPurpose.ACCOUNT_DELETION), any())).thenReturn(Optional.empty());
        when(tokens.consumeCode(eq(7), eq("22222222"), eq(TokenPurpose.ACCOUNT_DELETION), any())).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> userService.confirmDeletion(7, "11111111")).isInstanceOf(InvalidCodeException.class);
        verify(userRepository, never()).delete(any());

        userService.confirmDeletion(7, "22222222");
        verify(userRepository).delete(user);
    }

    @Test
    void askingForAnotherDeletionCodeTooSoonIsRefused() {
        when(userRepository.findById(7)).thenReturn(Optional.of(user));
        when(tokens.issue(7, TokenPurpose.ACCOUNT_DELETION)).thenReturn(false);

        assertThatThrownBy(() -> userService.requestDeletion(7)).isInstanceOf(TokenAlreadyExistsException.class);
    }
}
