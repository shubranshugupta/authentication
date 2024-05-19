package com.portfoliopro.auth.service.token.supplier;

import java.util.function.Supplier;

import com.portfoliopro.auth.entities.token.VerificationToken;

public class VerificationTokenSupplier implements Supplier<VerificationToken> {
    @Override
    public VerificationToken get() {
        return new VerificationToken();
    }
}
