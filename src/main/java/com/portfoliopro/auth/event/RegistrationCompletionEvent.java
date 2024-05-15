package com.portfoliopro.auth.event;

import org.springframework.context.ApplicationEvent;

import com.portfoliopro.auth.dto.TokenEmailDTO;
import com.portfoliopro.auth.entities.User;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegistrationCompletionEvent extends ApplicationEvent {
    private User user;
    private TokenEmailDTO tokenEmailDTO;

    public RegistrationCompletionEvent(User user, TokenEmailDTO tokenEmailDTO) {
        super(user);
        this.user = user;
        this.tokenEmailDTO = tokenEmailDTO;
    }
}
