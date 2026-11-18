package com.authcore.auth.utils;

public interface MessageBodyBuilder<T> {
    public String getMessage(T data);
}
