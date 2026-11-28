package com.authcore.auth.notification;

import java.time.Instant;

import org.jspecify.annotations.Nullable;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.authcore.auth.audit.AuditEvent;
import com.authcore.auth.audit.AuditLog;
import com.authcore.auth.common.EmailAddresses;
import com.authcore.auth.user.User;
import com.authcore.auth.user.UserRepository;

import lombok.RequiredArgsConstructor;

/**
 * The addresses not to email any more (M7e): SES said one bounced for good, or its owner
 * marked an email as spam. EmailListener skips them. Admins can take one off.
 */
@Service
@RequiredArgsConstructor
public class SuppressionList {
    public static final int MAX_PAGE_SIZE = 100;

    private final EmailSuppressionRepository suppressions;
    private final UserRepository userRepository;
    private final AuditLog audit;

    public boolean isSuppressed(String email) {
        return suppressions.existsByEmail(EmailAddresses.normalize(email));
    }

    /** Idempotent: SNS may deliver the same notification twice. */
    public void add(String email, EmailSuppression.Reason reason, @Nullable String detail) {
        String normalized = EmailAddresses.normalize(email);
        if (suppressions.existsByEmail(normalized))
            return;
        try {
            suppressions.saveAndFlush(new EmailSuppression(normalized, reason, truncate(detail), Instant.now()));
        } catch (DataIntegrityViolationException e) {
            return; // the same address at the same moment
        }
        // The audit log names accounts, never addresses (F2).
        audit.record(AuditEvent.EMAIL_SUPPRESSED, userId(normalized), "reason", reason);
    }

    public Page<EmailSuppression> list(int page, int size) {
        return suppressions.findAll(PageRequest.of(Math.max(page, 0), Math.clamp(size, 1, MAX_PAGE_SIZE),
                Sort.by(Sort.Direction.DESC, "createdAt")));
    }

    /** @return whether it was on the list */
    @Transactional
    public boolean remove(String email, Integer adminId) {
        String normalized = EmailAddresses.normalize(email);
        boolean removed = suppressions.deleteByEmail(normalized) > 0;
        if (removed)
            audit.record(AuditEvent.EMAIL_SUPPRESSION_REMOVED, userId(normalized), "by", adminId);
        return removed;
    }

    private @Nullable Integer userId(String email) {
        return userRepository.findByEmail(email).map(User::getId).orElse(null);
    }

    private static @Nullable String truncate(@Nullable String detail) {
        return detail == null || detail.length() <= 64 ? detail : detail.substring(0, 64);
    }
}
