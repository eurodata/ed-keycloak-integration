package de.eurodata.keycloak.util.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class Header {
    private final String key;
    private final String value;
}
