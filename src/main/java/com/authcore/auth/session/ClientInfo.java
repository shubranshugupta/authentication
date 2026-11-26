package com.authcore.auth.session;

import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Where a login or refresh comes from, so that users can recognise their sessions.
 *
 * @param device what the client calls itself (User-Agent); anyone can send anything here
 */
public record ClientInfo(String ip, @Nullable String device) {
    // The lengths of the database columns.
    private static final int MAX_IP = 45;
    private static final int MAX_DEVICE = 255;

    public ClientInfo {
        ip = cut(ip, MAX_IP);
        device = device == null ? null : cut(device, MAX_DEVICE);
    }

    public static ClientInfo of(HttpServletRequest request) {
        return new ClientInfo(request.getRemoteAddr(), request.getHeader(HttpHeaders.USER_AGENT));
    }

    private static String cut(String text, int max) {
        return text.length() <= max ? text : text.substring(0, max);
    }
}
