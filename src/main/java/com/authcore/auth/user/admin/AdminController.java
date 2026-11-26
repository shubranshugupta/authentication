package com.authcore.auth.user.admin;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.authcore.auth.common.MsgResponse;
import com.authcore.auth.security.PasswordConfirmation;
import com.authcore.auth.security.UserPrincipal;
import com.authcore.auth.session.ClientInfo;

import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

/**
 * Admin-only endpoints (role ADMIN). Not logged in: 401; logged in without the role: 403.
 * The actions that change something also ask for the admin's password, so a stolen access
 * token isn't enough for them. They are POST or PUT, because they need a body.
 */
@RestController
@RequestMapping("/api/v1/admin/users")
@PreAuthorize("hasRole('ADMIN')")
@RequiredArgsConstructor
@Tag(name = "Admin", description = "Users, for admins only")
public class AdminController {
    private final AdminUserService adminUserService;

    @GetMapping
    public ResponseEntity<AdminUserPageResponse> listUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "" + AdminUserService.DEFAULT_PAGE_SIZE) int size) {
        return ResponseEntity.ok(adminUserService.listUsers(page, size));
    }

    @GetMapping("/{id}")
    public ResponseEntity<AdminUserResponse> getUser(@PathVariable int id) {
        return ResponseEntity.ok(adminUserService.getUser(id));
    }

    @PostMapping("/{id}/lock")
    public ResponseEntity<AdminUserResponse> lock(@AuthenticationPrincipal UserPrincipal me, @PathVariable int id,
            @Valid @RequestBody AdminPasswordRequest request, HttpServletRequest http) {
        return ResponseEntity.ok(adminUserService.lock(confirmation(me, request.password(), http), id));
    }

    @PostMapping("/{id}/unlock")
    public ResponseEntity<AdminUserResponse> unlock(@AuthenticationPrincipal UserPrincipal me, @PathVariable int id,
            @Valid @RequestBody AdminPasswordRequest request, HttpServletRequest http) {
        return ResponseEntity.ok(adminUserService.unlock(confirmation(me, request.password(), http), id));
    }

    @PostMapping("/{id}/logout")
    public ResponseEntity<MsgResponse> logout(@AuthenticationPrincipal UserPrincipal me, @PathVariable int id,
            @Valid @RequestBody AdminPasswordRequest request, HttpServletRequest http) {
        adminUserService.endSessions(confirmation(me, request.password(), http), id);
        return ResponseEntity.ok(MsgResponse.builder().msg("Logged out of all devices.").build());
    }

    @PutMapping("/{id}/role")
    public ResponseEntity<AdminUserResponse> changeRole(@AuthenticationPrincipal UserPrincipal me, @PathVariable int id,
            @Valid @RequestBody ChangeRoleRequest request, HttpServletRequest http) {
        return ResponseEntity.ok(adminUserService.changeRole(confirmation(me, request.password(), http), id, request.role()));
    }

    private static PasswordConfirmation confirmation(UserPrincipal me, String password, HttpServletRequest http) {
        return new PasswordConfirmation(me.id(), password, ClientInfo.of(http).ip());
    }
}
