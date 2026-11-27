package com.authcore.auth.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionOperations;

import com.authcore.auth.common.AuthConfigProperties;
import com.authcore.auth.common.RetryingTransaction;
import com.authcore.auth.ratelimit.LoginThrottle;
import com.authcore.auth.ratelimit.TooManyRequestsException;
import com.authcore.auth.security.AccessToken;
import com.authcore.auth.audit.AuditLog;
import com.authcore.auth.security.InvalidTokenException;
import com.authcore.auth.security.JwtService;
import com.authcore.auth.security.LoginDetails;
import com.authcore.auth.security.PasswordConfirmation;
import com.authcore.auth.security.Reauthentication;
import com.authcore.auth.security.WrongPasswordException;
import com.authcore.auth.notification.SecurityAlert;
import com.authcore.auth.notification.SecurityNotifier;
import com.authcore.auth.session.ClientInfo;
import com.authcore.auth.session.DeviceService;
import com.authcore.auth.session.DeviceService.DeviceCheck;
import com.authcore.auth.session.SessionService;
import com.authcore.auth.session.SessionTokens;
import com.authcore.auth.token.InvalidCodeException;
import com.authcore.auth.token.OneTimeTokenService;
import com.authcore.auth.token.TokenPurpose;
import com.authcore.auth.user.Role;
import com.authcore.auth.user.User;
import com.authcore.auth.user.UserAlreadyExistsException;
import com.authcore.auth.user.UserRepository;

/** A5: the service needs no servlet API, so plain unit tests can cover it. */
@ExtendWith(MockitoExtension.class)
class AuthServiceTests {
    private static final String EMAIL = "jane@example.com";
    private static final ClientInfo CLIENT = new ClientInfo("203.0.113.7", "Firefox");
    private static final Duration WEEK = Duration.ofDays(7);

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtService jwtService;
    @Mock
    private SessionService sessions;
    @Mock
    private AuthenticationManager manager;
    @Mock
    private LoginThrottle loginThrottle;
    @Mock
    private OneTimeTokenService tokens;
    @Mock
    private Reauthentication reauthentication;
    @Mock
    private DeviceService devices;
    @Mock
    private SecurityNotifier notifier;

    private final AuthConfigProperties properties = new AuthConfigProperties();
    private AuthService authService;

    @BeforeEach
    void createService() {
        authService = new AuthService(userRepository, passwordEncoder, jwtService, sessions, manager,
                loginThrottle, tokens, new RetryingTransaction(TransactionOperations.withoutTransaction()), properties,
                new AuditLog(new SimpleMeterRegistry()), reauthentication, devices, notifier);
    }

    // ---- registration --------------------------------------------------------------

    @Test
    void registerSavesADisabledUserWithAHashedPasswordAndSendsTheEmail() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());
        when(passwordEncoder.encode("plain")).thenReturn("hash");
        when(userRepository.saveAndFlush(any())).thenAnswer(call -> call.getArgument(0));

        authService.register(request());

        User saved = registeredUser();
        assertThat(saved.getEmail()).isEqualTo(EMAIL);
        assertThat(saved.getPassword()).isEqualTo("hash");
        assertThat(saved.getRole()).isEqualTo(Role.USER);
        assertThat(saved.isEnabled()).isFalse();
        verify(tokens).issue(saved.getId(), TokenPurpose.EMAIL_VERIFICATION);
    }

    @Test
    void registerGivesListedEmailsTheAdminRole() {
        properties.setAdminEmails(List.of("Jane@Example.com"));
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());
        when(userRepository.saveAndFlush(any())).thenAnswer(call -> call.getArgument(0));

        authService.register(request());

        assertThat(registeredUser().getRole()).isEqualTo(Role.ADMIN);
    }

    @Test
    void registerRejectsATakenEmail() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user(true)));

        assertThatThrownBy(() -> authService.register(request())).isInstanceOf(UserAlreadyExistsException.class);
        verify(userRepository, never()).saveAndFlush(any());
        verifyNoInteractions(tokens);
    }

    @Test
    void registerRejectsAnEmailTakenAtTheSameMoment() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty(), Optional.of(user(false)));
        when(userRepository.saveAndFlush(any())).thenThrow(new DataIntegrityViolationException("duplicate"));

        assertThatThrownBy(() -> authService.register(request())).isInstanceOf(UserAlreadyExistsException.class);
    }

    @Test
    void registerDoesNotHideOtherDatabaseErrors() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());
        when(userRepository.saveAndFlush(any())).thenThrow(new DataIntegrityViolationException("other constraint"));

        assertThatThrownBy(() -> authService.register(request())).isInstanceOf(DataIntegrityViolationException.class);
    }

    // ---- login ---------------------------------------------------------------------

    @Test
    void loginReturnsBothTokens() {
        passwordIsRight();
        when(sessions.open(1, 5, CLIENT)).thenReturn(Optional.of(new SessionTokens(1, 5, 9L, "refresh", WEEK)));
        when(jwtService.generateToken(new AccessToken(1, 5, 9L))).thenReturn("access");

        when(devices.remember(1, "device")).thenReturn(new DeviceCheck("device", false));

        assertThat(authService.login("  Jane@Example.com ", "plain", CLIENT, "device"))
                .isEqualTo(new LoginResult(new TokenPair("access", "refresh", WEEK), "device"));
        verify(manager).authenticate(new UsernamePasswordAuthenticationToken(EMAIL, "plain"));
        verify(loginThrottle).beforeCheck(EMAIL, CLIENT.ip());
        verify(loginThrottle).succeeded(EMAIL, CLIENT.ip());
        verifyNoInteractions(notifier);
    }

    @Test
    void aLoginFromANewDeviceIsEmailedToTheOwner() {
        passwordIsRight();
        when(sessions.open(1, 5, CLIENT)).thenReturn(Optional.of(new SessionTokens(1, 5, 9L, "refresh", WEEK)));
        when(devices.remember(1, null)).thenReturn(new DeviceCheck("new-device", true));

        assertThat(authService.login(EMAIL, "plain", CLIENT, null).deviceId()).isEqualTo("new-device");
        verify(notifier).send(1, SecurityAlert.NEW_DEVICE_LOGIN, CLIENT);
    }

    @Test
    void aFailedLoginRemembersNoDeviceAndSendsNothing() {
        when(manager.authenticate(any())).thenThrow(new BadCredentialsException("Bad credentials"));

        assertThatThrownBy(() -> authService.login(EMAIL, "wrong", CLIENT, null)).isInstanceOf(BadCredentialsException.class);
        verifyNoInteractions(devices, notifier);
    }

    @Test
    void loginWithBadCredentialsOpensNoSession() {
        when(manager.authenticate(any())).thenThrow(new BadCredentialsException("Bad credentials"));

        assertThatThrownBy(() -> authService.login(EMAIL, "wrong", CLIENT, null)).isInstanceOf(BadCredentialsException.class);
        verifyNoInteractions(jwtService, sessions);
        // Only read, for the audit log's user id.
        verify(userRepository).findByEmail(EMAIL);
        verifyNoMoreInteractions(userRepository);
        verify(loginThrottle).beforeCheck(EMAIL, CLIENT.ip());
        verifyNoMoreInteractions(loginThrottle);
    }

    /** Checking one is expensive on purpose (bcrypt). */
    @Test
    void afterTooManyWrongPasswordsNoneIsChecked() {
        doThrow(new TooManyRequestsException(WEEK)).when(loginThrottle).beforeCheck(EMAIL, CLIENT.ip());

        assertThatThrownBy(() -> authService.login(EMAIL, "plain", CLIENT, null)).isInstanceOf(TooManyRequestsException.class);
        verifyNoInteractions(manager, sessions);
    }

    /** A database outage must not lock everybody out. */
    @Test
    void onlyWrongPasswordsCountAsGuesses() {
        when(manager.authenticate(any())).thenThrow(new InternalAuthenticationServiceException("database is down"));

        assertThatThrownBy(() -> authService.login(EMAIL, "plain", CLIENT, null)).isInstanceOf(InternalAuthenticationServiceException.class);
        verify(loginThrottle).notAGuess(EMAIL, CLIENT.ip());
    }

    @Test
    void loginOfAnAccountThatChangedMeanwhileIsJustBadCredentials() {
        passwordIsRight();
        when(sessions.open(1, 5, CLIENT)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(EMAIL, "plain", CLIENT, null)).isInstanceOf(BadCredentialsException.class);
        verifyNoInteractions(jwtService);
    }

    @Test
    void aRefreshWithoutANewRefreshTokenStillReturnsAnAccessToken() {
        when(sessions.refresh("used", CLIENT)).thenReturn(new SessionTokens(1, 0, 9L, null, WEEK));
        when(jwtService.generateToken(new AccessToken(1, 0, 9L))).thenReturn("access");

        assertThat(authService.refresh("used", CLIENT)).isEqualTo(new TokenPair("access", null, WEEK));
    }

    @Test
    void tokensAreNotPrinted() {
        assertThat(new TokenPair("access", "refresh", WEEK).toString()).doesNotContain("access").doesNotContain("refresh");
        assertThat(new SessionTokens(1, 0, 9L, "refresh", WEEK).toString()).doesNotContain("refresh");
    }

    // ---- requests that must not reveal accounts (H2) -----------------------------------

    @Test
    void resendAndResetRequestsDoNothingForUnknownEmails() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

        authService.resendVerification(EMAIL);
        authService.requestPasswordReset(EMAIL);

        verifyNoInteractions(tokens);
    }

    @Test
    void onlyUnverifiedAccountsGetTheVerificationEmailAgain() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user(true)));
        authService.resendVerification(EMAIL);
        verifyNoInteractions(tokens);

        User unverified = user(false);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(unverified));
        authService.resendVerification(EMAIL);
        verify(tokens).issue(unverified.getId(), TokenPurpose.EMAIL_VERIFICATION);
    }

    @Test
    void onlyVerifiedAccountsGetAResetCode() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user(false)));
        authService.requestPasswordReset(EMAIL);
        verifyNoInteractions(tokens);

        User verified = user(true);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(verified));
        authService.requestPasswordReset(EMAIL);
        verify(tokens).issue(verified.getId(), TokenPurpose.PASSWORD_RESET);
    }

    @Test
    void askingAgainDuringTheCooldownIsNotAnError() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user(true)));
        when(tokens.issue(any(), any())).thenReturn(false);

        assertThatCode(() -> authService.requestPasswordReset(EMAIL)).doesNotThrowAnyException();
    }

    @Test
    void aWrongCodeGetsTheSameAnswerAsAnUnknownAccount() {
        when(userRepository.findByEmail("unknown@example.com")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("unverified@example.com")).thenReturn(Optional.of(user(false)));
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user(true)));
        when(tokens.consumeCode(any(), any(), any(), any())).thenReturn(Optional.empty());

        for (String email : List.of("unknown@example.com", "unverified@example.com", EMAIL))
            assertThatThrownBy(() -> authService.resetPassword(email, "12345678", "new", CLIENT))
                    .isInstanceOf(InvalidCodeException.class).hasMessage(AuthService.INVALID_CODE);
        verify(userRepository, never()).save(any());
        verifyNoInteractions(passwordEncoder, sessions, loginThrottle);
    }

    // ---- verification and reset ----------------------------------------------------

    @Test
    void verifyEmailEnablesTheAccountOfTheLink() {
        User user = user(false);
        when(tokens.consumeLink("token", TokenPurpose.EMAIL_VERIFICATION)).thenReturn(Optional.of(user));

        authService.verifyEmail("token");

        assertThat(savedUser().isEnabled()).isTrue();
    }

    @Test
    void verifyEmailRejectsAnInvalidLink() {
        when(tokens.consumeLink(any(), any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.verifyEmail("token"))
                .isInstanceOf(InvalidCodeException.class).hasMessage(AuthService.INVALID_VERIFICATION_LINK);
        verify(userRepository, never()).save(any());
    }

    @Test
    void resetPasswordStoresTheHashAndEndsEverySession() {
        User user = user(true);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(tokens.consumeCode(eq(1), eq("12345678"), eq(TokenPurpose.PASSWORD_RESET), any())).thenReturn(Optional.of(user));
        when(passwordEncoder.encode("new")).thenReturn("new-hash");

        authService.resetPassword(" Jane@Example.com", "12345678", "new", CLIENT);

        assertThat(savedUser().getPassword()).isEqualTo("new-hash");
        verify(sessions).endAll(user);
        verify(loginThrottle).passwordChanged(EMAIL, CLIENT.ip());
        verify(notifier).send(1, SecurityAlert.PASSWORD_RESET, CLIENT);
    }

    // ---- helpers -------------------------------------------------------------------

    private void passwordIsRight() {
        User user = user(true);
        user.setTokenVersion(5);
        when(manager.authenticate(any()))
                .thenReturn(new UsernamePasswordAuthenticationToken(new LoginDetails(user), null, List.of()));
    }

    private User registeredUser() {
        ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
        verify(userRepository).saveAndFlush(saved.capture());
        return saved.getValue();
    }

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

    // ---- change password -----------------------------------------------------------

    private static final String IP = "203.0.113.7";

    private User userWithVersion(int version) {
        return User.builder().id(7).email(EMAIL).password("old-hash").role(Role.USER).enabled(true)
                .tokenVersion(version).build();
    }

    @Test
    void changePasswordKeepsThisSessionAndGivesItANewAccessToken() {
        User user = userWithVersion(3);
        when(reauthentication.check(new PasswordConfirmation(7, "current", IP))).thenReturn(userWithVersion(3));
        when(passwordEncoder.encode("new")).thenReturn("new-hash");
        when(userRepository.findAndLockById(7)).thenReturn(Optional.of(user));
        when(sessions.endAllExcept(user, 42L)).thenReturn(Optional.of(new SessionTokens(7, 4, 42L, null, WEEK)));
        when(jwtService.generateToken(new AccessToken(7, 4, 42L))).thenReturn("access");

        assertThat(authService.changePassword(7, 42L, "current", "new", CLIENT)).isEqualTo("access");

        assertThat(user.getPassword()).isEqualTo("new-hash");
        verify(loginThrottle).passwordChanged(EMAIL, IP);
        verify(notifier).send(7, SecurityAlert.PASSWORD_CHANGED, CLIENT);
    }

    @Test
    void aWrongCurrentPasswordChangesNothing() {
        when(reauthentication.check(any())).thenThrow(new WrongPasswordException());

        assertThatThrownBy(() -> authService.changePassword(7, 42L, "wrong", "new", CLIENT))
                .isInstanceOf(WrongPasswordException.class);

        verifyNoInteractions(userRepository, sessions, jwtService, notifier);
    }

    /** E.g. a password reset between the check and the change: it ended this session too. */
    @Test
    void aPasswordChangedSinceTheCheckIsNotOverwritten() {
        User user = userWithVersion(4);
        when(reauthentication.check(any())).thenReturn(userWithVersion(3));
        when(userRepository.findAndLockById(7)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.changePassword(7, 42L, "current", "new", CLIENT))
                .isInstanceOf(InvalidTokenException.class);

        assertThat(user.getPassword()).isEqualTo("old-hash");
        verifyNoInteractions(sessions, jwtService, notifier);
        verify(loginThrottle, never()).passwordChanged(any(), any());
    }

    @Test
    void anEndedSessionGetsNoNewAccessToken() {
        User user = userWithVersion(3);
        when(reauthentication.check(any())).thenReturn(userWithVersion(3));
        when(userRepository.findAndLockById(7)).thenReturn(Optional.of(user));
        when(sessions.endAllExcept(user, 42L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.changePassword(7, 42L, "current", "new", CLIENT))
                .isInstanceOf(InvalidTokenException.class);

        verifyNoInteractions(jwtService, notifier);
        verify(loginThrottle, never()).passwordChanged(any(), any());
    }
}
