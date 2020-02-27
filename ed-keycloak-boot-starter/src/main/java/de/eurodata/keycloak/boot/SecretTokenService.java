package de.eurodata.keycloak.boot;

import de.eurodata.keycloak.util.SecretTokenAuthenticator;

public interface SecretTokenService {


    SecretToken registerSecureSecret(String secret, String... authorities);

    SecretTokenAuthenticator createAuthenticator(String secret);

    boolean contains(String secret);

    SecretToken retrieve(String secret);

}
