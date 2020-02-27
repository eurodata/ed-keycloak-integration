/*
 * Eurodata AG
 *
 * Copyright 2018 Eurodata AG.
 */
package de.eurodata.keycloak.boot;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * @author cbuerckert
 */
public class SecretTokenAuthenticationProvider implements AuthenticationProvider {

    private final SecretTokenService tokenService;
    private final Supplier<EurodataAccountService> userServiceSupplier;


    public SecretTokenAuthenticationProvider(SecretTokenService tokenService, Supplier<EurodataAccountService> userServiceSupplier) {
        this.tokenService = tokenService;
        this.userServiceSupplier = userServiceSupplier;
    }


    @Override
    public Authentication authenticate(Authentication authentication) {
        String token = (String) authentication.getPrincipal();
        if (!tokenService.contains(token)) {
            return null;
        }
        EurodataAccountService userService = userServiceSupplier.get();
        if (userService != null) {
            SecretToken auth = tokenService.retrieve(token);
            Set<String> authorities = auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
            Set<? extends EurodataAuthority> extended = userService.loadAccountAuthorities(auth.getName(), authorities);

            return new SecretToken(auth.getPrincipal(), auth.getCredentials(), extended, auth.getAccountInfo());
        }
        return tokenService.retrieve(token);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(SecretToken.class);
    }

}
