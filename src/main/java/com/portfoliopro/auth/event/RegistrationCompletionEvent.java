package com.portfoliopro.auth.event;

import org.springframework.context.ApplicationEvent;

import com.portfoliopro.auth.entities.User;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegistrationCompletionEvent extends ApplicationEvent {
    private User user;
    private String appUrl;

    public RegistrationCompletionEvent(User user, String appUrl) {
        super(user);
        this.user = user;
        this.appUrl = appUrl;
    }
}
