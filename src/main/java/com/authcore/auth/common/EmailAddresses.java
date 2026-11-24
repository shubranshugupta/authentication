package com.authcore.auth.common;

import java.util.Locale;

/**
 * One canonical form for emails: trimmed and lowercase. Applied before every save
 * and lookup, so " Jane@Example.com" and "jane@example.com" are the same account
 * (and the same cache key).
 */
public final class EmailAddresses {
    private EmailAddresses() {
    }

    public static String normalize(String email) {
        return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }
}
