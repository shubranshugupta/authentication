package com.authcore.auth.event;

import org.springframework.context.ApplicationEvent;

import com.authcore.auth.dto.EmailDTO;
import com.authcore.auth.entities.User;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DeleteAccountEvent extends ApplicationEvent {
    private User user;
    private EmailDTO deleteAccountDTO;

    public DeleteAccountEvent(User user, EmailDTO deleteAccountDTO) {
        super(user);
        this.user = user;
        this.deleteAccountDTO = deleteAccountDTO;
    }

}
