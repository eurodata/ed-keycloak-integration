/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.eurodata.keycloak.boot;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author cbuerckert
 */
@Slf4j
@Controller
@RequestMapping(path = "${keycloak-client.prefix:/}")
public class EurodataKeycloakRestController {

    private final String redirectUrl;

    @Value("${keycloak-client.url:}")
    private String url;
    @Value("${keycloak-client.realm:}")
    private String realm;
    @Value("${keycloak-client.clientId:}")
    private String clientId;

    public EurodataKeycloakRestController(@Autowired AdapterConfig config) {
        if (config.getAuthServerUrl().endsWith("/")) {
            redirectUrl = config.getAuthServerUrl() + "js/keycloak.js";
        } else {
            redirectUrl = config.getAuthServerUrl() + "/js/keycloak.js";
        }
    }

    @CrossOrigin
    @GetMapping(value = "keycloak.js")
    @ResponseBody
    public void keycloakJs(HttpServletResponse response) throws IOException {
        response.sendRedirect(redirectUrl);
    }

    @CrossOrigin
    @GetMapping(value = "keycloak-client-config")
    @ResponseBody
    public KeycloakClientConfig keycloakClientConfig() {
        if (url.isEmpty() || realm.isEmpty() || clientId.isEmpty()) {
            log.warn("Request to /keycloak-client-config is missing relevant information. Configure keycloak-client.[url,realm,clientId] in your application.yml. Response contains empty values. ");
        }
        return new KeycloakClientConfig(url, realm, clientId);
    }

    @AllArgsConstructor
    @Data
    public static class KeycloakClientConfig {
        private String url;
        private String realm;
        private String clientId;
    }

}
