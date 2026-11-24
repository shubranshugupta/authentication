package com.authcore.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.authcore.auth.config.properties.AuthConfigProperties;
import com.authcore.auth.dto.request.RegisterRequest;
import com.authcore.auth.entities.RefreshToken;
import com.authcore.auth.entities.Role;
import com.authcore.auth.entities.User;
import com.authcore.auth.exception.InvalidTokenException;
import com.authcore.auth.exception.TokenAlreadyExistsException;
import com.authcore.auth.exception.UserAlreadyExistsException;
import com.authcore.auth.repository.UserRepository;
import com.authcore.auth.service.token.TokenType;

/** A5: the service needs no servlet API, so plain unit tests can cover it. */
@ExtendWith(MockitoExtension.class)
class AuthServiceTests {
    private static final String EMAIL = "jane@example.com";

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtService jwtService;
    @Mock
    private RefreshTokenService refreshTokenService;
    @Mock
    private AuthenticationManager manager;
    @Mock
    private TokenServiceFacade tokenService;

    private final AuthConfigProperties properties = new AuthConfigProperties();
    private AuthService authService;

    @BeforeEach
    void createService() {
        authService = new AuthService(userRepository, passwordEncoder, jwtService, refreshTokenService, manager,
                tokenService, properties);
    }

    // ---- registration --------------------------------------------------------------

    @Test
    void registerSavesADisabledUserWithAHashedPasswordAndSendsTheEmail() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());
        when(passwordEncoder.encode("plain")).thenReturn("hash");
        when(userRepository.save(any())).thenAnswer(call -> call.getArgument(0));

        authService.register(request());

        User saved = savedUser();
        assertThat(saved.getEmail()).isEqualTo(EMAIL);
        assertThat(saved.getPassword()).isEqualTo("hash");
        assertThat(saved.getRole()).isEqualTo(Role.USER);
        assertThat(saved.isEnabled()).isFalse();
        verify(tokenService).createTokenAndSendMail(saved, TokenType.VERIFICATION_TOKEN);
    }

    @Test
    void registerGivesListedEmailsTheAdminRole() {
        properties.setAdminEmails(List.of("Jane@Example.com"));
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());
        when(userRepository.save(any())).thenAnswer(call -> call.getArgument(0));

        authService.register(request());

        assertThat(savedUser().getRole()).isEqualTo(Role.ADMIN);
    }

    @Test
    void registerRejectsATakenEmail() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user(true)));

        assertThatThrownBy(() -> authService.register(request())).isInstanceOf(UserAlreadyExistsException.class);
        verify(userRepository, never()).save(any());
        verifyNoInteractions(tokenService);
    }

    @Test
    void registerRejectsAnEmailTakenAtTheSameMoment() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty(), Optional.of(user(false)));
        when(userRepository.save(any())).thenThrow(new DataIntegrityViolationException("duplicate"));

        assertThatThrownBy(() -> authService.register(request())).isInstanceOf(UserAlreadyExistsException.class);
    }

    @Test
    void registerDoesNotHideOtherDatabaseErrors() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());
        when(userRepository.save(any())).thenThrow(new DataIntegrityViolationException("other constraint"));

        assertThatThrownBy(() -> authService.register(request())).isInstanceOf(DataIntegrityViolationException.class);
    }

    // ---- login ---------------------------------------------------------------------

    @Test
    void loginReturnsBothTokens() {
        User user = user(true);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(jwtService.generateToken(EMAIL)).thenReturn("access");
        when(refreshTokenService.createRefreshToken(user))
                .thenReturn(RefreshToken.builder().refreshToken("refresh").build());

        assertThat(authService.login("  Jane@Example.com ", "plain")).isEqualTo(new TokenPair("access", "refresh"));
    }

    @Test
    void loginWithBadCredentialsNeverLooksUpTheUser() {
        when(manager.authenticate(any())).thenThrow(new BadCredentialsException("Bad credentials"));

        assertThatThrownBy(() -> authService.login(EMAIL, "wrong")).isInstanceOf(BadCredentialsException.class);
        verifyNoInteractions(userRepository, jwtService, refreshTokenService);
    }

    @Test
    void loginOfAnAccountDeletedMeanwhileIsJustBadCredentials() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(EMAIL, "plain")).isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void aTokenPairDoesNotPrintItsTokens() {
        assertThat(new TokenPair("access", "refresh").toString()).doesNotContain("access").doesNotContain("refresh");
    }

    // ---- requests that must not reveal accounts (H2) -----------------------------------

    @Test
    void resendAndResetRequestsDoNothingForUnknownEmails() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

        authService.resendVerification(EMAIL);
        authService.requestPasswordReset(EMAIL);

        verifyNoInteractions(tokenService);
    }

    @Test
    void onlyUnverifiedAccountsGetTheVerificationEmailAgain() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user(true)));
        authService.resendVerification(EMAIL);
        verifyNoInteractions(tokenService);

        User unverified = user(false);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(unverified));
        authService.resendVerification(EMAIL);
        verify(tokenService).createTokenAndSendMail(unverified, TokenType.VERIFICATION_TOKEN);
    }

    @Test
    void onlyVerifiedAccountsGetAResetCode() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user(false)));
        authService.requestPasswordReset(EMAIL);
        verifyNoInteractions(tokenService);

        User verified = user(true);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(verified));
        authService.requestPasswordReset(EMAIL);
        verify(tokenService).createTokenAndSendMail(verified, TokenType.RESET_PASSWORD_TOKEN);
    }

    @Test
    void askingAgainWhileACodeIsActiveIsNotAnError() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user(true)));
        when(tokenService.createTokenAndSendMail(any(), any())).thenThrow(new TokenAlreadyExistsException("active"));

        assertThatCode(() -> authService.requestPasswordReset(EMAIL)).doesNotThrowAnyException();
    }

    @Test
    void aWrongTokenGetsTheSameAnswerAsAnUnknownAccount() {
        when(userRepository.findByEmail("unknown@example.com")).thenReturn(Optional.empty());
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user(true)));
        doThrow(new InvalidTokenException("internal text")).when(tokenService).verifyToken(any(), any(), any());

        assertThatThrownBy(() -> authService.resetPassword("unknown@example.com", "123456", "new"))
                .isInstanceOf(InvalidTokenException.class).hasMessage(AuthService.INVALID_OTP);
        assertThatThrownBy(() -> authService.resetPassword(EMAIL, "123456", "new"))
                .isInstanceOf(InvalidTokenException.class).hasMessage(AuthService.INVALID_OTP);
        verify(userRepository, never()).save(any());
    }

    // ---- verification and reset ----------------------------------------------------

    @Test
    void verifyEmailChecksTheTokenBeforeEnablingTheAccount() {
        User user = user(false);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));

        authService.verifyEmail(EMAIL, "token");

        InOrder order = Mockito.inOrder(tokenService, userRepository);
        order.verify(tokenService).verifyToken(user, "token", TokenType.VERIFICATION_TOKEN);
        order.verify(userRepository).save(user);
        assertThat(user.isEnabled()).isTrue();
    }

    @Test
    void resetPasswordStoresTheHashAndDeletesTheRefreshToken() {
        User user = user(true);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(passwordEncoder.encode("new")).thenReturn("new-hash");

        authService.resetPassword(EMAIL, "123456", "new");

        assertThat(savedUser().getPassword()).isEqualTo("new-hash");
        verify(refreshTokenService).deleteRefreshToken(user);
    }

    // ---- helpers -------------------------------------------------------------------

    private User savedUser() {
        ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(saved.capture());
        return saved.getValue();
    }

    private static RegisterRequest request() {
        return RegisterRequest.builder().firstName("jane").email(" Jane@Example.com").password("plain").build();
    }

    private static User user(boolean enabled) {
        return User.builder().id(1).email(EMAIL).password("old-hash").role(Role.USER).enabled(enabled).build();
    }
}
