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

    /**
     * Enough of an address for its owner to recognize it, e.g. "j***@example.com", but not
     * enough to write to it.
     */
    public static String mask(String email) {
        int at = email.lastIndexOf('@');
        return at < 1 ? "***" : email.charAt(0) + "***" + email.substring(at);
    }
}
