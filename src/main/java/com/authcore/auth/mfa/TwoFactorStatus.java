package com.authcore.auth.mfa;

/** @param recoveryCodesLeft unused recovery codes; 0 while it's off */
public record TwoFactorStatus(boolean enabled, int recoveryCodesLeft) {
}
