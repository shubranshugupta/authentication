package com.authcore.auth.security;

import java.io.IOException;
import java.time.Instant;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import com.authcore.auth.session.UserSessionRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/** Logs the request in with its access token ("Authorization: Bearer ..."), if it has one. */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {
    private static final String BEARER = "Bearer ";

    private final JwtService jwtService;
    private final UserSessionRepository sessionRepository;
    private final HandlerExceptionResolver exceptionResolver;

    // An explicit constructor: Lombok's would drop the @Qualifier.
    public JwtAuthFilter(JwtService jwtService, UserSessionRepository sessionRepository,
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver exceptionResolver) {
        this.jwtService = jwtService;
        this.sessionRepository = sessionRepository;
        this.exceptionResolver = exceptionResolver;
    }

    /**
     * Public endpoints ignore access tokens: a client whose token has expired must still be
     * able to refresh it, even if it sends the old one along.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return SecurityConfig.PUBLIC.matches(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith(BEARER)
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                authenticate(header.substring(BEARER.length()), request);
            } catch (Exception e) {
                exceptionResolver.resolveException(request, response, null, e);
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private void authenticate(String token, HttpServletRequest request) {
        AccessToken accessToken = jwtService.parse(token);
        UserPrincipal principal = sessionRepository
                .findUserOfActiveSession(accessToken.sessionId(), accessToken.userId(), Instant.now())
                // The version was raised since, e.g. by a password reset (H6).
                .filter(user -> user.getTokenVersion() == accessToken.tokenVersion())
                .filter(user -> !user.isLocked())
                .map(user -> UserPrincipal.from(user, accessToken.sessionId()))
                .orElseThrow(() -> new InvalidTokenException(JwtService.INVALID_TOKEN));

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                principal, null, principal.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
