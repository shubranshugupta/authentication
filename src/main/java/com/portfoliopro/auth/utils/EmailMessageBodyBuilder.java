package com.portfoliopro.auth.utils;

public interface EmailMessageBodyBuilder<T> extends MessageBodyBuilder<T> {
    public String getMessage(T data);
}
