package com.authcore.auth.user;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

/** Read-only user lookups for admins. Changing users comes in Phase 5. */
@Service
@RequiredArgsConstructor
public class AdminUserService {
    public static final int DEFAULT_PAGE_SIZE = 20;
    public static final int MAX_PAGE_SIZE = 100;

    private final UserRepository userRepository;

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
}
