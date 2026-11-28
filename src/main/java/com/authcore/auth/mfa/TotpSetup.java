package com.authcore.auth.mfa;

/**
 * What the user's authenticator app needs: either the key typed in, or the URI as a QR code.
 * Shown once; only an encrypted copy is kept.
 *
 * @param secret     base32, as apps take it
 * @param otpauthUri for a QR code (the frontend draws it)
 */
public record TotpSetup(String secret, String otpauthUri) {
    /** Leaves the secret out: logs must not contain it. */
    @Override
    public String toString() {
        return "TotpSetup[...]";
    }
}
