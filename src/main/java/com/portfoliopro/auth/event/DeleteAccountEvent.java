package com.portfoliopro.auth.event;

import org.springframework.context.ApplicationEvent;

import com.portfoliopro.auth.dto.TokenEmailDTO;
import com.portfoliopro.auth.entities.User;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DeleteAccountEvent extends ApplicationEvent {
    private User user;
    private TokenEmailDTO deleteAccountDTO;

    public DeleteAccountEvent(User user, TokenEmailDTO deleteAccountDTO) {
        super(user);
        this.user = user;
        this.deleteAccountDTO = deleteAccountDTO;
    }

}
