package com.portfoliopro.auth.utils;

public interface MessageBodyBuilder<T> {
    public String getMessage(T data);
}
