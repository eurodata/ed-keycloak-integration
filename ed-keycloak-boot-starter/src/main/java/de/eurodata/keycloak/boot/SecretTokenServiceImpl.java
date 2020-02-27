/*
 * Eurodata AG
 *
 * Copyright 2018 Eurodata AG.
 */
package de.eurodata.keycloak.boot;

import de.eurodata.keycloak.util.AuthenticatorFactory;
import de.eurodata.keycloak.util.SecretTokenAuthenticator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.HashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author cbuerckert
 */
@Slf4j
public class SecretTokenServiceImpl implements SecretTokenService {

    private final HashMap<String, SecretToken> store = new HashMap<>();


    @Override
    public SecretToken registerSecureSecret(String secret, String... authorities) {
        SecretToken secretToken = new SecretToken(secret, null,
                Stream.of(authorities)
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList()), new SecretTokenAccountInfo(secret));
        secretToken.setAuthenticated(true);
        store.put(secret, secretToken);
        return secretToken;
    }

    @Override
    public boolean contains(String secret) {
        return store.containsKey(secret);
    }

    @Override
    public SecretTokenAuthenticator createAuthenticator(String secret) {
        return AuthenticatorFactory.getDefault().createSharedSecret(secret);
    }

    @Override
    public SecretToken retrieve(String secret) {
        return store.get(secret);
    }

}
