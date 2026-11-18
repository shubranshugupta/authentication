package com.authcore.auth.event;

import org.springframework.context.ApplicationEvent;

import com.authcore.auth.dto.EmailDTO;
import com.authcore.auth.entities.User;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PasswordResetEvent extends ApplicationEvent {
    private User user;
    private EmailDTO passwordResetDTO;

    public PasswordResetEvent(User user, EmailDTO passwordResetDTO) {
        super(user);
        this.user = user;
        this.passwordResetDTO = passwordResetDTO;
    }
}
