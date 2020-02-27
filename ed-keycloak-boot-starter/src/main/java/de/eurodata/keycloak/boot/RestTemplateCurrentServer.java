/*
 * Eurodata AG
 *
 * Copyright 2018 cbuerckert.
 */
package de.eurodata.keycloak.boot;

import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

/**
 *
 * @author cbuerckert
 */
public class RestTemplateCurrentServer extends RestTemplate {

    public RestTemplateCurrentServer(ClientHttpRequestFactory requestFactory) {
        super(requestFactory);
    }

}
