package de.eurodata.keycloak.boot;

import lombok.Data;
import lombok.RequiredArgsConstructor;

import java.io.Serializable;

@RequiredArgsConstructor
@Data
public class SecretTokenAccountInfo implements Serializable {

    private static final long serialVersionUID = 520L;

    final String accountId;
    String username;
    String name;
    String firstName;
    String lastName;
    String email;
    String title;
    String salutation;
}
