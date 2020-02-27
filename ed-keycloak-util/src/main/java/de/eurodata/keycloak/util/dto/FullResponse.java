package de.eurodata.keycloak.util.dto;

import lombok.Data;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;
import java.util.Map;

@Data
public class FullResponse {
    private int status;
    private String message;
    private Map<String, List<String>> headers;
    private String content;


    public static FullResponse get(HttpsURLConnection connection) throws IOException {
        // getResponseCode, connect, getInputStream or getOutputStream executes the request
        FullResponse response = new FullResponse();
        response.setStatus(connection.getResponseCode());
        response.setMessage(connection.getResponseMessage());
        response.setHeaders(connection.getHeaderFields());
        BufferedReader in;

        if (response.getStatus() > 299) {
            in = new BufferedReader(
                    new InputStreamReader(connection.getErrorStream())
            );
        } else {
            in = new BufferedReader(
                    new InputStreamReader(connection.getInputStream())
            );
        }
        String inputLine;
        StringBuilder content = new StringBuilder();
        while ((inputLine = in.readLine()) != null) {
            content.append(inputLine);
        }
        in.close();
        response.setContent(content.toString());
        return response;
    }
}
