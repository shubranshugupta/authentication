package com.authcore.auth.user.account;

import java.util.HashMap;
import java.util.Map;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.authcore.auth.audit.AuditEvent;
import com.authcore.auth.audit.AuditLog;
import com.authcore.auth.common.EmailAddresses;
import com.authcore.auth.common.RetryingTransaction;
import com.authcore.auth.notification.SecurityNotifier;
import com.authcore.auth.ratelimit.LoginThrottle;
import com.authcore.auth.security.PasswordConfirmation;
import com.authcore.auth.security.Reauthentication;
import com.authcore.auth.session.ClientInfo;
import com.authcore.auth.session.SessionService;
import com.authcore.auth.token.InvalidCodeException;
import com.authcore.auth.token.OneTimeTokenService;
import com.authcore.auth.token.TokenAlreadyExistsException;
import com.authcore.auth.token.TokenPurpose;
import com.authcore.auth.user.User;
import com.authcore.auth.user.UserAlreadyExistsException;
import com.authcore.auth.user.UserRepository;

import lombok.RequiredArgsConstructor;

/**
 * Changing the email of an account (F5), in three steps:
 * <ol>
 * <li>The logged-in user types their password and the new address, which is sent a code.</li>
 * <li>They type the code, and the account has the new address. The old address is sent a
 * link that changes it back for 7 days: whoever knew the password could otherwise take
 * the account, since password reset codes now go to their address.</li>
 * <li>Only if that wasn't the owner: the link changes the email back, sets a new password
 * and logs out every device.</li>
 * </ol>
 * While that link works, the email can't be changed again, and no other account can take
 * the old address. Sessions stay: the email isn't a credential, and access tokens hold the
 * user id.
 */
@Service
@RequiredArgsConstructor
public class EmailChangeService {
    static final String INVALID_CODE = "The code is wrong or has expired.";
    static final String INVALID_UNDO_LINK = "The link is invalid, or was already used, or has expired.";
    static final String TAKEN = "Another account already uses this email.";

    private final UserRepository userRepository;
    private final OneTimeTokenService tokens;
    private final RetryingTransaction transaction;
    private final Reauthentication reauthentication;
    private final PasswordEncoder passwordEncoder;
    private final SessionService sessions;
    private final LoginThrottle loginThrottle;
    private final AuditLog audit;

    /**
     * Sends a code to the new address.
     *
     * @throws com.authcore.auth.security.WrongPasswordException if the password is wrong
     * @throws UserAlreadyExistsException  if another account has the address
     * @throws EmailChangeRefusedException if it's the current address, or the last change can
     *                                     still be undone
     * @throws TokenAlreadyExistsException if a code was sent less than a minute ago
     */
    public void request(Integer userId, String password, String newEmail, ClientInfo client) {
        User user = reauthentication.check(new PasswordConfirmation(userId, password, client.ip()));
        String email = EmailAddresses.normalize(newEmail);
        if (email.equals(user.getEmail()))
            throw new EmailChangeRefusedException("This is already your email.");
        if (isTaken(email))
            throw new UserAlreadyExistsException(TAKEN);
        boolean sent = transaction.run(() -> {
            if (tokens.hasUnused(userId, TokenPurpose.EMAIL_CHANGE_UNDO))
                throw new EmailChangeRefusedException("Your email was changed less than 7 days ago. Until"
                        + " then, the link sent to your old address can still change it back.");
            return tokens.issue(userId, TokenPurpose.EMAIL_CHANGE, email);
        });
        if (!sent)
            throw new TokenAlreadyExistsException("A code was sent less than a minute ago. Check your inbox, or try again in a minute.");
    }

    /**
     * Gives the account the address the code was sent to, and sends the old address the link
     * that changes it back.
     *
     * @throws InvalidCodeException       if the code is wrong or has expired
     * @throws UserAlreadyExistsException if another account took the address meanwhile
     */
    public void confirm(Integer userId, String code, ClientInfo client) {
        boolean changed;
        try {
            changed = transaction.run(() -> tokens
                    .consumeCodeForEmail(userId, code, TokenPurpose.EMAIL_CHANGE, user -> true)
                    .map(consumed -> {
                        User user = consumed.user();
                        String oldEmail = user.getEmail();
                        String newEmail = consumed.email();
                        // Throwing rolls the used code back: it's the right one.
                        if (isTaken(newEmail))
                            throw new UserAlreadyExistsException(TAKEN);
                        user.setEmail(newEmail);
                        userRepository.saveAndFlush(user);
                        // A reset code sent to the old address mustn't work for the new one.
                        tokens.revoke(userId, TokenPurpose.PASSWORD_RESET, TokenPurpose.ACCOUNT_DELETION);
                        tokens.issueNow(user, TokenPurpose.EMAIL_CHANGE_UNDO, oldEmail, details(newEmail, client));
                        return true;
                    }).orElse(false));
        } catch (DataIntegrityViolationException e) {
            // Registered at the same moment: the unique constraint rejected this one.
            throw new UserAlreadyExistsException(TAKEN, e);
        }
        if (!changed)
            throw new InvalidCodeException(INVALID_CODE);
        audit.record(AuditEvent.EMAIL_CHANGED, userId);
    }

    /**
     * Changes the email back to the address the link was sent to, sets a new password, and
     * logs out every device: whoever changed the email knew the old password.
     *
     * @throws InvalidCodeException if the link isn't valid
     */
    public void undo(String token, String newPassword, ClientInfo client) {
        String passwordHash = passwordEncoder.encode(newPassword);
        User undone;
        try {
            undone = transaction.run(() -> tokens.consumeLinkForEmail(token, TokenPurpose.EMAIL_CHANGE_UNDO)
                    .map(consumed -> {
                        User user = consumed.user();
                        user.setEmail(consumed.email());
                        user.setPassword(passwordHash);
                        userRepository.saveAndFlush(user);
                        sessions.endAll(user);
                        // Codes sent to the address it had, which may not be the owner's.
                        tokens.revoke(user.getId(), TokenPurpose.PASSWORD_RESET, TokenPurpose.ACCOUNT_DELETION,
                                TokenPurpose.EMAIL_CHANGE);
                        return user;
                    }).orElse(null));
        } catch (DataIntegrityViolationException e) {
            // Only if registered at the same moment: registration checks isTaken first.
            throw new UserAlreadyExistsException(TAKEN, e);
        }
        if (undone == null)
            throw new InvalidCodeException(INVALID_UNDO_LINK);
        loginThrottle.passwordChanged(undone.getEmail(), client.ip());
        audit.record(AuditEvent.EMAIL_CHANGE_UNDONE, undone.getId());
    }

    /**
     * Whether an account has this address, or an undo link can still give it back to one.
     * Registration checks the same.
     */
    public boolean isTaken(String email) {
        return userRepository.findByEmail(email).isPresent() || tokens.isReservedForUndo(email);
    }

    private static Map<String, Object> details(String newEmail, ClientInfo client) {
        Map<String, Object> details = new HashMap<>(SecurityNotifier.whenAndWhere(client));
        details.put("newEmail", EmailAddresses.mask(newEmail));
        return details;
    }
}
