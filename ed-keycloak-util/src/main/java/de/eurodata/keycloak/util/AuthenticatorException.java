package de.eurodata.keycloak.util;

public class AuthenticatorException extends RuntimeException {
    public AuthenticatorException(String message) {
        super(message);
    }

    public AuthenticatorException(String message, Throwable err) {
        super(message, err);
    }
}
