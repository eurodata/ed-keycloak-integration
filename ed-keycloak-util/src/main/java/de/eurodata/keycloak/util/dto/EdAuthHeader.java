package de.eurodata.keycloak.util.dto;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class EdAuthHeader {
    private final String key;
    private final String value;
}
