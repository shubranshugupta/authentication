package com.authcore.auth.user.admin;

import java.time.Instant;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.authcore.auth.common.MsgResponse;
import com.authcore.auth.common.NormalizedEmailDeserializer;
import com.authcore.auth.notification.EmailSuppression;
import com.authcore.auth.notification.SuppressionList;
import com.authcore.auth.security.PasswordConfirmation;
import com.authcore.auth.security.Reauthentication;
import com.authcore.auth.security.UserPrincipal;
import com.authcore.auth.session.ClientInfo;

import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import tools.jackson.databind.annotation.JsonDeserialize;

/**
 * The addresses that aren't emailed any more, because SES reported a permanent bounce or a
 * complaint (M7e). Admins only; taking one off needs the admin's password.
 */
@RestController
@RequestMapping("/api/v1/admin/email-suppressions")
@PreAuthorize("hasRole('ADMIN')")
@RequiredArgsConstructor
@Tag(name = "Admin", description = "Users, for admins only")
public class EmailSuppressionController {
    private final SuppressionList suppressionList;
    private final Reauthentication reauthentication;

    /** Newest first; at most 100 per page. */
    @GetMapping
    public ResponseEntity<SuppressionPage> list(@RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Page<EmailSuppression> found = suppressionList.list(page, size);
        return ResponseEntity.ok(new SuppressionPage(found.map(Suppression::from).getContent(), found.getNumber(),
                found.getSize(), found.getTotalElements(), found.getTotalPages()));
    }

    /**
     * Takes an address off the list, e.g. once its owner fixed their mailbox. If it bounces
     * again, it goes back on.
     */
    @PostMapping("/remove")
    public ResponseEntity<MsgResponse> remove(@AuthenticationPrincipal UserPrincipal me,
            @Valid @RequestBody RemoveRequest request, HttpServletRequest http) {
        reauthentication.check(new PasswordConfirmation(me.id(), request.password(), ClientInfo.of(http).ip()));
        boolean removed = suppressionList.remove(request.email(), me.id());
        return ResponseEntity.ok(MsgResponse.builder()
                .msg(removed ? "Taken off the suppression list." : "It wasn't on the suppression list.").build());
    }

    public record Suppression(String email, EmailSuppression.Reason reason, String detail, Instant createdAt) {
        static Suppression from(EmailSuppression suppression) {
            return new Suppression(suppression.getEmail(), suppression.getReason(), suppression.getDetail(),
                    suppression.getCreatedAt());
        }
    }

    public record SuppressionPage(List<Suppression> items, int page, int size, long totalElements, int totalPages) {
    }

    /** @param password the admin's own */
    public record RemoveRequest(
            @NotBlank @Email @Size(max = 254) @JsonDeserialize(using = NormalizedEmailDeserializer.class) String email,
            @NotBlank @Size(max = 256) String password) {
        @Override
        public String toString() {
            return "RemoveRequest[]";
        }
    }
}
