package de.eurodata.keycloak.boot;

import org.springframework.security.core.GrantedAuthority;

public class EurodataAuthority implements GrantedAuthority {

    private final String authority;

    public EurodataAuthority(String authority) {
        this.authority = authority;
    }

    @Override
    public String getAuthority() {
        return authority;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof GrantedAuthority)) return false;

        GrantedAuthority that = (GrantedAuthority) o;

        return getAuthority().equals(that.getAuthority());
    }

    @Override
    public int hashCode() {
        return getAuthority().hashCode();
    }

    @Override
    public String toString() {
        return "ed(" + authority + ")";
    }
}
