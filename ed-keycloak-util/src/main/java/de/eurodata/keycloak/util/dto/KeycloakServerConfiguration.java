package de.eurodata.keycloak.util.dto;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.eurodata.keycloak.util.AuthenticatorException;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.net.Proxy;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.function.Supplier;

@NoArgsConstructor
@AllArgsConstructor
@Data
@Slf4j
public class KeycloakServerConfiguration {
    private static final int CONNECTION_TIMEOUT = 5000;
    private static final int CONNECTION_READ_TIMEOUT = 5000;
    private static final int MAX_CONNECTION_RETRIES = 3;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private String url;
    private String realm;
    private String clientId;

    public static Supplier<KeycloakServerConfiguration> createStatic(String url, String realm, String clientId) {
        KeycloakServerConfiguration config = new KeycloakServerConfiguration(url, realm, clientId);
        return () -> config;
    }

    public static Supplier<KeycloakServerConfiguration> createDynamicResolver(Supplier<String> url, Proxy proxy) {
        return () -> {
            FullResponse response;
            int tries = 0;
            while (true) {
                try {
                    HttpsURLConnection con = createConnection(url.get(), proxy);
                    response = FullResponse.get(con);
                    con.disconnect();
                    break;
                } catch (SocketTimeoutException ste) {
                    log.warn("Connection to server timed out while retrieving keycloak server configuration. Retrying.", ste);
                    if (tries >= MAX_CONNECTION_RETRIES) {
                        throw new AuthenticatorException("Maximum of connection retries to retrieve keycloak server configuration reached.", ste);
                    }
                } catch (IOException ioe) {
                    throw new AuthenticatorException("IO Error on connection creation.", ioe);
                }
                tries++;
            }
            if (response.getStatus() > 299) {
                throw new AuthenticatorException("Requests failed with status " + response.getStatus()
                        + " and Message " + response.getMessage()
                        + ". Response was " + response.getContent());
            }
            try {
                return OBJECT_MAPPER.readValue(response.getContent(), KeycloakServerConfiguration.class);
            } catch (JsonProcessingException jpe) {
                throw new AuthenticatorException("Could not process keycloak config response json string from server: " + response.getContent(), jpe);
            } catch (IOException io) {
                throw new AuthenticatorException("Cannot open connection.", io);
            }
        };
    }

    public static Supplier<KeycloakServerConfiguration> createResolver(String url, Proxy proxy) {
        return createDynamicResolver(() -> url, proxy);
    }

    private static HttpsURLConnection createConnection(String serverBaseUrl, Proxy proxy) throws IOException {
        URL url = new URL(serverBaseUrl + "/api/keycloak/keycloak-client-config");
        HttpsURLConnection con = (HttpsURLConnection) url.openConnection(proxy);
        con.setRequestMethod("GET");
        con.setRequestProperty("Accept", "application/json");
        con.setInstanceFollowRedirects(true);
        con.setConnectTimeout(CONNECTION_TIMEOUT);
        con.setReadTimeout(CONNECTION_READ_TIMEOUT);
        return con;
    }
}
