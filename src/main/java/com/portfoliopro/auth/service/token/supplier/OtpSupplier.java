package com.portfoliopro.auth.service.token.supplier;

import java.util.function.Supplier;

import com.portfoliopro.auth.entities.token.Otp;

public class OtpSupplier implements Supplier<Otp> {

    @Override
    public Otp get() {
        return new Otp();
    }

}
