package com.authcore.auth.security;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.authcore.auth.user.Role;
import com.authcore.auth.user.User;

/**
 * The logged-in user, as Spring Security and the controllers see it
 * ({@code @AuthenticationPrincipal UserPrincipal me}). Separate from the {@link User}
 * entity, so the password hash and the other columns stay out of the security context.
 */
public record UserPrincipal(Integer id, String email, Role role, boolean enabled, Long sessionId)
        implements UserDetails {

    public static UserPrincipal from(User user, Long sessionId) {
        return new UserPrincipal(user.getId(), user.getEmail(), user.getRole(), user.isEnabled(), sessionId);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Spring's hasRole('ADMIN') checks for the authority "ROLE_ADMIN".
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override
    public String getUsername() {
        return email;
    }

    /** Already authenticated by the access token, so there is no password here. */
    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
