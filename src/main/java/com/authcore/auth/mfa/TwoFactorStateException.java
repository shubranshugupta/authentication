package com.authcore.auth.mfa;

import com.authcore.auth.common.ErrorCode;

import lombok.Getter;

/** Two-factor authentication is on when it must be off, or the other way round. */
@Getter
public class TwoFactorStateException extends RuntimeException {
    private final ErrorCode code;

    public TwoFactorStateException(ErrorCode code, String message) {
        super(message);
        this.code = code;
    }
}
