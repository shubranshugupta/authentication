package com.authcore.auth.dto.response;

import java.util.List;

/** One page of users. page is zero-based. */
public record AdminUserPageResponse(
        List<AdminUserResponse> users,
        int page,
        int size,
        long totalElements,
        int totalPages) {
}
