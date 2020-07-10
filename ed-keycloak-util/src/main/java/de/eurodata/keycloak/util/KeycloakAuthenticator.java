package de.eurodata.keycloak.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.eurodata.keycloak.util.dto.*;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Time;
import org.keycloak.representations.AccessToken;

import javax.net.ssl.HttpsURLConnection;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

@Slf4j
public abstract class KeycloakAuthenticator implements Authenticator {

    private static final int CONNECTION_TIMEOUT = 5000;
    private static final int CONNECTION_READ_TIMEOUT = 5000;

    private final ObjectMapper mapper;
    private final Supplier<KeycloakServerConfiguration> configurationSupplier;
    private final Proxy proxy;

    private KeycloakTokenResponse keycloakTokenResponse;
    private AccessToken currentToken;
    private KeycloakServerConfiguration currentConfiguration;

    // ClientServerAuthenticator
    KeycloakAuthenticator(Supplier<KeycloakServerConfiguration> serverConfigurationSupplier, Proxy proxy) {
        this.configurationSupplier = serverConfigurationSupplier;
        this.mapper = new ObjectMapper();
        this.proxy = proxy;
    }


    @Override
    public final EdAuthHeader getHeader() {
        return new EdAuthHeader("Authorization", "Bearer " + this.getValidToken());
    }

    private String getValidToken() {
        int verificationRetry = 3;
        for (int i = 0; i < verificationRetry; i++) {
            try {
                int refreshBefore = 5;
                if (keycloakTokenResponse == null
                        || currentToken == null
                        || getActiveSeconds() <= refreshBefore
                        || !currentToken.isActive(refreshBefore)) {
                    String tokenString = requestToken();
                    currentToken = TokenVerifier.create(tokenString, AccessToken.class)
                            .withDefaultChecks()
                            .getToken();
                    return keycloakTokenResponse.getAccessToken();
                }
                return keycloakTokenResponse.getAccessToken();
            } catch (VerificationException ve) {
                keycloakTokenResponse = null;
                log.warn("Keycloak Verification failed. Retry {}/{}", i, verificationRetry, ve);
            }
        }
        throw new AuthenticatorException("Could not retrieve keycloak token.");
    }

    private int getActiveSeconds() {
        if (currentToken == null) {
            return 0;
        }
        return currentToken.getExpiration() - Time.currentTime();
    }

    private String requestToken() {
        FullResponse response;
        try {
            HttpsURLConnection keycloakServerConnection = getNewConnection();
            response = FullResponse.get(keycloakServerConnection);
            keycloakServerConnection.disconnect();
        } catch (IOException ioe) {
            throw new AuthenticatorException("Error while creating the connection to the keycloak server.", ioe);
        }
        if (response.getStatus() > 299) {
            throw new AuthenticatorException("Requests failed with status " + response.getStatus()
                    + " and Message " + response.getMessage()
                    + ". Response was " + response.getContent());
        }

        try {
            keycloakTokenResponse = mapper.readValue(response.getContent(), KeycloakTokenResponse.class);
            currentToken = TokenVerifier.create(keycloakTokenResponse.getAccessToken(), AccessToken.class)
                    .withDefaultChecks()
                    .getToken();

        } catch (JsonProcessingException jpe) {
            throw new AuthenticatorException("Error while processing response token from keycloak server.", jpe);
        } catch (VerificationException ve) {
            throw new AuthenticatorException("The keycloak token received could not be verified.", ve);
        } catch (IOException io) {
            throw new AuthenticatorException("Error reading token response", io);
        }
        return keycloakTokenResponse.getAccessToken();
    }

    protected abstract Header[] getHeaders(KeycloakServerConfiguration currentConfiguration);

    private HttpsURLConnection getNewConnection() throws IOException {
        if (currentConfiguration == null) {
            currentConfiguration = configurationSupplier.get();
        }
        return createConnection(currentConfiguration.getUrl(),
                currentConfiguration.getRealm(),
                getHeaders(currentConfiguration)
        );
    }


    private HttpsURLConnection createConnection(String authUrl, String realm, Header... headers) throws IOException {
        URL url = new URL(authUrl + "/realms/" + realm + "/protocol/openid-connect/token");
        HttpsURLConnection con = (HttpsURLConnection) url.openConnection(proxy);
        con.setRequestMethod("POST");
        con.setRequestProperty("Accept", "application/json");
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

        Map<String, String> params = new HashMap<>();
        if (headers.length != 0) {
            for (Header header : headers) {
                params.put(header.getKey(), header.getValue());
            }
        }
        con.setDoOutput(true);
        DataOutputStream dos = new DataOutputStream(con.getOutputStream());
        dos.writeBytes(getParamsString(params));
        dos.flush();
        dos.close();
        con.setInstanceFollowRedirects(true);
        con.setConnectTimeout(CONNECTION_TIMEOUT);
        con.setReadTimeout(CONNECTION_READ_TIMEOUT);
        return con;
    }

    private String getParamsString(Map<String, String> params) throws UnsupportedEncodingException {
        StringBuilder result = new StringBuilder();

        for (Map.Entry<String, String> entry : params.entrySet()) {
            result.append(URLEncoder.encode(entry.getKey(), "UTF-8"));
            result.append("=");
            result.append(URLEncoder.encode(entry.getValue(), "UTF-8"));
            result.append("&");
        }

        String resultString = result.toString();
        return resultString.length() > 0
                ? resultString.substring(0, resultString.length() - 1)
                : resultString;
    }
}
