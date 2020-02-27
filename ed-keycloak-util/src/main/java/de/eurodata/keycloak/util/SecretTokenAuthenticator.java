package de.eurodata.keycloak.util;

import de.eurodata.keycloak.util.dto.EdAuthHeader;

public class SecretTokenAuthenticator implements Authenticator {

    public static final String HEADER_KEY = "X-Secret-Token";

    private final String secret;

    SecretTokenAuthenticator(String secret) {
        this.secret = secret;
    }

    @Override
    public EdAuthHeader getHeader() {
        return new EdAuthHeader(HEADER_KEY, secret);
    }
}
