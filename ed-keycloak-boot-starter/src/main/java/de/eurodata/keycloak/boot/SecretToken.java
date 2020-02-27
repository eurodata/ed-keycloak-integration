/*
 * Eurodata AG
 *
 * Copyright 2018 Eurodata AG.
 */
package de.eurodata.keycloak.boot;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.util.Collection;

/**
 * @author cbuerckert
 */
@Getter
@EqualsAndHashCode(callSuper = true)
public class SecretToken extends PreAuthenticatedAuthenticationToken {

    private final SecretTokenAccountInfo accountInfo;

    public SecretToken(Object aPrincipal, Object aCredentials, SecretTokenAccountInfo accountInfo) {
        super(aPrincipal, aCredentials);
        this.accountInfo = accountInfo;
    }

    public SecretToken(Object aPrincipal, Object aCredentials, Collection<? extends GrantedAuthority> anAuthorities, SecretTokenAccountInfo accountInfo) {
        super(aPrincipal, aCredentials, anAuthorities);
        this.accountInfo = accountInfo;
    }

}
