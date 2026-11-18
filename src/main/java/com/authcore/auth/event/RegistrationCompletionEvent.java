package com.authcore.auth.event;

import org.springframework.context.ApplicationEvent;

import com.authcore.auth.dto.EmailDTO;
import com.authcore.auth.entities.User;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegistrationCompletionEvent extends ApplicationEvent {
    private User user;
    private EmailDTO tokenEmailDTO;

    public RegistrationCompletionEvent(User user, EmailDTO tokenEmailDTO) {
        super(user);
        this.user = user;
        this.tokenEmailDTO = tokenEmailDTO;
    }
}
