package com.authcore.auth.social;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import org.jspecify.annotations.Nullable;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.authcore.auth.audit.AuditEvent;
import com.authcore.auth.audit.AuditLog;
import com.authcore.auth.common.AuthConfigProperties;
import com.authcore.auth.common.EmailAddresses;
import com.authcore.auth.common.RetryingTransaction;
import com.authcore.auth.notification.SecurityAlert;
import com.authcore.auth.notification.SecurityNotifier;
import com.authcore.auth.session.ClientInfo;
import com.authcore.auth.token.OneTimeTokenService;
import com.authcore.auth.token.TokenPurpose;
import com.authcore.auth.user.Role;
import com.authcore.auth.user.User;
import com.authcore.auth.user.UserRepository;

import lombok.RequiredArgsConstructor;

/**
 * Finds or makes the account for someone Google has just signed in (F5), and hands out the
 * one-minute code the web app exchanges for tokens.
 *
 * <ul>
 * <li>A Google account seen before signs in to the account it was linked to, whatever its
 * email is now.</li>
 * <li>Otherwise, only an email Google says is verified is used. An account with that email
 * gets Google linked: a verified one is told by email; an unverified one is taken over, and
 * its password removed, since anyone could have registered it with that address.</li>
 * <li>Without one, a new account is made, with an unusable random password: "Forgot
 * password" sets a real one.</li>
 * </ul>
 * Two-factor authentication is asked for when the code is exchanged, like after a password.
 */
@Service
@ConditionalOnExpression(GoogleSignInConfig.ENABLED)
@RequiredArgsConstructor
public class SocialLoginService {
    static final String PROVIDER = "GOOGLE";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final UserRepository userRepository;
    private final SocialIdentityRepository identities;
    private final OneTimeTokenService tokens;
    private final RetryingTransaction transaction;
    private final PasswordEncoder passwordEncoder;
    private final AuthConfigProperties properties;
    private final AuditLog audit;
    private final SecurityNotifier notifier;

    /** What Google says about the person, from its ID token. */
    public record GoogleProfile(String subject, @Nullable String email, boolean emailVerified,
            @Nullable String givenName, @Nullable String familyName) {
    }

    /**
     * @return the code for the web app to exchange
     * @throws SocialLoginException if this person can't sign in
     */
    public String signIn(GoogleProfile profile, ClientInfo client) {
        // Hashed outside the transaction: bcrypt is slow on purpose.
        String unusablePassword = passwordEncoder.encode(randomPassword());
        SignIn signIn;
        try {
            signIn = transaction.run(() -> resolve(profile, unusablePassword));
        } catch (DataIntegrityViolationException e) {
            // The same Google account, or the same email, at the same moment: the other one
            // made the account or the link, which this attempt now finds.
            signIn = transaction.run(() -> resolve(profile, unusablePassword));
        }
        switch (signIn.how()) {
            case CREATED -> audit.record(AuditEvent.GOOGLE_SIGN_UP, signIn.userId());
            case LINKED -> {
                audit.record(AuditEvent.GOOGLE_LINKED, signIn.userId());
                notifier.send(signIn.userId(), SecurityAlert.GOOGLE_LINKED, client);
            }
            case TAKEN_OVER -> audit.record(AuditEvent.GOOGLE_LINKED, signIn.userId(), "unverifiedAccount", true);
            case KNOWN -> {
            }
        }
        return signIn.code();
    }

    private SignIn resolve(GoogleProfile profile, String unusablePassword) {
        Instant now = Instant.now();
        Optional<SocialIdentity> known = identities.findByProviderAndSubject(PROVIDER, profile.subject());
        if (known.isPresent()) {
            User user = lock(known.get().getUserId());
            known.get().signedIn(now);
            return signIn(user, How.KNOWN);
        }

        if (!profile.emailVerified() || !StringUtils.hasText(profile.email()))
            throw new SocialLoginException(SocialLoginException.EMAIL_NOT_VERIFIED);
        String email = EmailAddresses.normalize(profile.email());
        Optional<User> existing = userRepository.findByEmail(email).map(user -> lock(user.getId()));

        User user;
        How how;
        if (existing.isPresent()) {
            user = existing.get();
            if (identities.existsByUserIdAndProvider(user.getId(), PROVIDER))
                // Linked to another Google account already, which once had this email.
                throw new SocialLoginException(SocialLoginException.OTHER_GOOGLE_ACCOUNT);
            how = user.isEnabled() ? How.LINKED : How.TAKEN_OVER;
            if (!user.isEnabled()) {
                user.setEnabled(true);
                user.setPassword(unusablePassword);
                user.setFirstName(firstName(profile, email));
                user.setLastName(profile.familyName());
                tokens.revoke(user.getId(), TokenPurpose.values());
            }
        } else {
            // An email change could still be undone to it (EmailChangeService).
            if (tokens.isReservedForUndo(email))
                throw new SocialLoginException(SocialLoginException.EMAIL_UNAVAILABLE);
            user = User.builder()
                    .firstName(firstName(profile, email))
                    .lastName(profile.familyName())
                    .email(email)
                    .password(unusablePassword)
                    .role(properties.isAdminEmail(email) ? Role.ADMIN : Role.USER)
                    .enabled(true)
                    .build();
            how = How.CREATED;
        }
        user = userRepository.saveAndFlush(user);
        identities.saveAndFlush(new SocialIdentity(user.getId(), PROVIDER, profile.subject(), now));
        return signIn(user, how);
    }

    private SignIn signIn(User user, How how) {
        if (user.isLocked())
            throw new SocialLoginException(SocialLoginException.ACCOUNT_LOCKED);
        return new SignIn(user.getId(), how, tokens.issueUnsent(user, TokenPurpose.SOCIAL_LOGIN));
    }

    private User lock(Integer userId) {
        // Found a moment ago; deleted since is as good as never there.
        return userRepository.findAndLockById(userId)
                .orElseThrow(() -> new SocialLoginException(SocialLoginException.FAILED));
    }

    private static String firstName(GoogleProfile profile, String email) {
        if (StringUtils.hasText(profile.givenName()))
            return profile.givenName();
        return email.substring(0, email.indexOf('@'));
    }

    private static String randomPassword() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    private enum How {
        KNOWN, LINKED, TAKEN_OVER, CREATED
    }

    private record SignIn(Integer userId, How how, String code) {
    }
}
