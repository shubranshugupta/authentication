package com.authcore.auth.user;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

/**
 * Admin-only endpoints (role ADMIN). Not logged in: 401; logged in without the
 * role: 403. Uses the /api/v1 paths planned for every endpoint (A6), so these
 * won't move later.
 */
@RestController
@RequestMapping("/api/v1/admin/users")
@PreAuthorize("hasRole('ADMIN')")
@RequiredArgsConstructor
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
}
