package de.eurodata.keycloak.util;

import de.eurodata.keycloak.util.dto.EdAuthHeader;

import java.util.function.Supplier;

public interface Authenticator extends Supplier<EdAuthHeader> {

    EdAuthHeader getHeader();

    @Override
    default EdAuthHeader get() {
        return getHeader();
    }
}
