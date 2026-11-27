package com.authcore.auth.user.account;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

/** @param otp the code sent to the new address */
public record ConfirmEmailChangeRequest(
        @NotNull @Pattern(regexp = "\\d{8}", message = "must be the 8 digits from the email") String otp) {

    @Override
    public String toString() {
        return "ConfirmEmailChangeRequest[]";
    }
}
