package com.authcore.auth.user.admin;

import java.time.Instant;
import java.util.function.Consumer;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import com.authcore.auth.audit.AuditEvent;
import com.authcore.auth.audit.AuditLog;
import com.authcore.auth.common.AuthConfigProperties;
import com.authcore.auth.common.RetryingTransaction;
import com.authcore.auth.security.PasswordConfirmation;
import com.authcore.auth.security.Reauthentication;
import com.authcore.auth.session.SessionService;
import com.authcore.auth.user.Role;
import com.authcore.auth.user.User;
import com.authcore.auth.user.UserNotFoundException;
import com.authcore.auth.user.UserRepository;

import lombok.RequiredArgsConstructor;

/**
 * What admins can do with other users. Admins can't lock or demote themselves, so nobody
 * locks themselves out by mistake. Every change needs the admin's password.
 */
@Service
@RequiredArgsConstructor
public class AdminUserService {
    public static final int DEFAULT_PAGE_SIZE = 20;
    public static final int MAX_PAGE_SIZE = 100;

    private final UserRepository userRepository;
    private final SessionService sessions;
    private final RetryingTransaction transaction;
    private final AuthConfigProperties properties;
    private final Reauthentication reauthentication;
    private final AuditLog audit;

    /** Users ordered by id. Out-of-range page numbers and sizes are clamped. */
    public AdminUserPageResponse listUsers(int page, int size) {
        int safePage = Math.max(page, 0);
        int safeSize = Math.clamp(size, 1, MAX_PAGE_SIZE);
        Page<User> users = userRepository.findAll(PageRequest.of(safePage, safeSize, Sort.by("id")));

        return new AdminUserPageResponse(
                users.map(AdminUserResponse::from).getContent(),
                users.getNumber(),
                users.getSize(),
                users.getTotalElements(),
                users.getTotalPages());
    }

    public AdminUserResponse getUser(int id) {
        return userRepository.findById(id)
                .map(AdminUserResponse::from)
                .orElseThrow(() -> new UserNotFoundException(id));
    }

    /** Logs the user out everywhere, and keeps them out until they are unlocked. */
    public AdminUserResponse lock(PasswordConfirmation admin, Integer id) {
        reauthentication.check(admin);
        refuseSelf(admin.userId(), id);
        AdminUserResponse user = change(id, found -> {
            if (!found.isLocked())
                found.setLockedAt(Instant.now());
            sessions.endAll(found);
        });
        audit.record(AuditEvent.USER_LOCKED, id, "by", admin.userId());
        return user;
    }

    public AdminUserResponse unlock(PasswordConfirmation admin, Integer id) {
        reauthentication.check(admin);
        AdminUserResponse user = change(id, found -> found.setLockedAt(null));
        audit.record(AuditEvent.USER_UNLOCKED, id, "by", admin.userId());
        return user;
    }

    public void endSessions(PasswordConfirmation admin, Integer id) {
        reauthentication.check(admin);
        change(id, sessions::endAll);
        audit.record(AuditEvent.USER_LOGGED_OUT, id, "by", admin.userId());
    }

    /** Takes effect with the user's next request: roles are never read from tokens. */
    public AdminUserResponse changeRole(PasswordConfirmation admin, Integer id, Role role) {
        reauthentication.check(admin);
        refuseSelf(admin.userId(), id);
        AdminUserResponse user = change(id, found -> {
            if (role != Role.ADMIN && properties.isAdminEmail(found.getEmail()))
                throw new AdminActionRefusedException(
                        "This email is listed in AUTH_ADMIN_EMAILS, so the next start would make the user an admin again. Remove it there first.");
            found.setRole(role);
        });
        audit.record(AuditEvent.ROLE_CHANGED, id, "role", role, "by", admin.userId());
        return user;
    }

    private AdminUserResponse change(Integer id, Consumer<User> change) {
        return transaction.run(() -> {
            User user = userRepository.findAndLockById(id).orElseThrow(() -> new UserNotFoundException(id));
            change.accept(user);
            return AdminUserResponse.from(userRepository.save(user));
        });
    }

    private static void refuseSelf(Integer adminId, Integer id) {
        if (adminId.equals(id))
            throw new AdminActionRefusedException("Admins can't do this to themselves.");
    }
}
