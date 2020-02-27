package de.eurodata.keycloak.util;

import de.eurodata.keycloak.util.dto.Header;
import de.eurodata.keycloak.util.dto.KeycloakServerConfiguration;

import java.net.Proxy;
import java.util.function.Supplier;


public class AuthenticatorFactory {
    private static final AuthenticatorFactory DEFAULT = new AuthenticatorFactory(Proxy.NO_PROXY);
    private static final String HEADER_GRANT_TYPE = "grant_type";
    private static final String HEADER_VALUE_PASS = "password";
    private static final String HEADER_VALUE_CLIENT_CREDENTIALS = "client_credentials";
    private static final String HEADER_CLIENT_ID = "client_id";
    private static final String HEADER_CLIENT_SECRET = "client_secret";
    private static final String HEADER_USERNAME = "username";
    private static final String HEADER_PASS = "password";
    private final Proxy proxy;

    public AuthenticatorFactory(Proxy proxy) {
        this.proxy = proxy;
    }

    public static AuthenticatorFactory getDefault() {
        return DEFAULT;
    }

    public SecretTokenAuthenticator createSharedSecret(String sharedSecret) {
        return new SecretTokenAuthenticator(sharedSecret);
    }

    private KeycloakAuthenticator cs(Supplier<KeycloakServerConfiguration> config, String username, String password) {
        return new KeycloakAuthenticator(config, proxy) {
            @Override
            protected Header[] getHeaders(KeycloakServerConfiguration currentConfig) {
                return new Header[]{
                        new Header(HEADER_GRANT_TYPE, HEADER_VALUE_PASS),
                        new Header(HEADER_USERNAME, username),
                        new Header(HEADER_PASS, password),
                        new Header(HEADER_CLIENT_ID, currentConfig.getClientId())
                };
            }
        };
    }

    private KeycloakAuthenticator ss(Supplier<KeycloakServerConfiguration> config, String clientSecret) {
        return new KeycloakAuthenticator(config, proxy) {
            @Override
            protected Header[] getHeaders(KeycloakServerConfiguration currentConfig) {
                return new Header[]{
                        new Header(HEADER_GRANT_TYPE, HEADER_VALUE_CLIENT_CREDENTIALS),
                        new Header(HEADER_CLIENT_SECRET, clientSecret),
                        new Header(HEADER_CLIENT_ID, currentConfig.getClientId())
                };
            }
        };
    }


    public KeycloakAuthenticator createUserPassword(String configUrl, String username, String password) {
        return cs(KeycloakServerConfiguration.createResolver(configUrl, proxy), username, password);
    }

    public KeycloakAuthenticator createClientSecret(String configUrl, String clientSecret) {
        return ss(KeycloakServerConfiguration.createResolver(configUrl, proxy), clientSecret);
    }

    public KeycloakAuthenticator createUserPassword(Supplier<String> configUrlSupplier, String username, String password) {
        return cs(KeycloakServerConfiguration.createDynamicResolver(configUrlSupplier, proxy), username, password);
    }

    public KeycloakAuthenticator createClientSecret(Supplier<String> configUrlSupplier, String clientSecret) {
        return ss(KeycloakServerConfiguration.createDynamicResolver(configUrlSupplier, proxy), clientSecret);
    }

    public KeycloakAuthenticator createUserPassword(String authUrl, String realm, String clientId, String username, String password) {
        return cs(KeycloakServerConfiguration.createStatic(authUrl, realm, clientId), username, password);
    }

    public KeycloakAuthenticator createClientSecret(String authUrl, String realm, String clientId, String clientSecret) {
        return ss(KeycloakServerConfiguration.createStatic(authUrl, realm, clientId), clientSecret);
    }

}
