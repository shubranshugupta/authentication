package com.authcore.auth.security;

import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.authcore.auth.user.User;

import lombok.Getter;

/** What the password check at login needs, and who it found. */
@Getter
public class LoginDetails extends org.springframework.security.core.userdetails.User {
    private final Integer id;
    private final int tokenVersion;

    public LoginDetails(User user) {
        super(user.getEmail(), user.getPassword(), user.isEnabled(), true, true, true,
                List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name())));
        this.id = user.getId();
        this.tokenVersion = user.getTokenVersion();
    }
}
