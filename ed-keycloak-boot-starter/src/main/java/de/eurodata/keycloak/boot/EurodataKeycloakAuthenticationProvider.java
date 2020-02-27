package de.eurodata.keycloak.boot;

import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;

import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class EurodataKeycloakAuthenticationProvider implements AuthenticationProvider {


    private final Supplier<EurodataAccountService> userServiceSupplier;

    public EurodataKeycloakAuthenticationProvider(Supplier<EurodataAccountService> userServiceSupplier) {
        this.userServiceSupplier = userServiceSupplier;
    }

    private String keycloakRole2Authority(String keycloakRole) {
        return "ROLE_" + keycloakRole.toUpperCase();
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) authentication;
        Set<String> givenKeycloakRoles = token
                .getAccount()
                .getRoles()
                .stream()
                .map(this::keycloakRole2Authority)
                .collect(Collectors.toSet());

        EurodataAccountService userService = userServiceSupplier.get();

        Set<? extends EurodataAuthority> authorities =
                userService == null
                        ? givenKeycloakRoles.stream().map(EurodataAuthority::new).collect(Collectors.toSet())
                        : userService.loadAccountAuthorities(token.getName(), givenKeycloakRoles);

        return new KeycloakAuthenticationToken(token.getAccount(), token.isInteractive(), authorities);
    }


    @Override
    public boolean supports(Class<?> aClass) {
        return KeycloakAuthenticationToken.class.isAssignableFrom(aClass);
    }

}

