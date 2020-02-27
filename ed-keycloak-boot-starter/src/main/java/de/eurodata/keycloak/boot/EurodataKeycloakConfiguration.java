/*
 * Eurodata AG
 *
 * Copyright 2018 cbuerckert.
 */
package de.eurodata.keycloak.boot;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.keycloak.adapters.springboot.KeycloakSpringBootProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

/**
 *
 * @author cbuerckert
 */
@Retention(value = RetentionPolicy.RUNTIME)
@Target(value = {ElementType.TYPE})
@Documented
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(KeycloakSpringBootProperties.class)
public @interface EurodataKeycloakConfiguration {

}
