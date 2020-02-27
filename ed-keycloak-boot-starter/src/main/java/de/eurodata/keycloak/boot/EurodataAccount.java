package de.eurodata.keycloak.boot;

import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@ToString
public class EurodataAccount {

    private final String id;
    private final Collection<GrantedAuthority> authorities;
    private String username;
    private String displayName;
    private String firstname;
    private String lastname;
    private String email;
    private String title;
    private String salutation;
    private String accountUrl;
    private String accountUrlWithReferrer;
    private Map<String, Object> data = new HashMap<>();

    public EurodataAccount(String id, Collection<GrantedAuthority> authorities) {
        this.authorities = authorities;
        this.id = id;
    }

    public Collection<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public String getId() {
        return id;
    }

    public boolean hasAuthority(String authority) {
        return authorities.contains(new EurodataAuthority(authority));
    }

    public boolean hasAuthority(EurodataAuthority authority) {
        return authorities.contains(authority);
    }

    public Optional<String> username() {
        return Optional.ofNullable(username);
    }

    public <T> void set(DataKey<T> key, T value) {
        data.put(key.identifier, value);
    }

    public <T> Optional<T> get(DataKey<T> key) {
        return key.cast(data.get(key.identifier));
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Optional<String> salutation() {
        return Optional.ofNullable(salutation);
    }

    public void setSalutation(String salutation) {
        this.salutation = salutation;
    }

    public Optional<String> title() {
        return Optional.ofNullable(title);
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public Optional<String> firstname() {
        return Optional.ofNullable(firstname);
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public Optional<String> lastname() {
        return Optional.ofNullable(lastname);
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    public Optional<String> email() {
        return Optional.ofNullable(email);
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Optional<String> displayName() {
        return Optional.ofNullable(displayName);
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public Optional<String> accountUrl() {
        return Optional.ofNullable(accountUrl);
    }

    public void setAccountUrl(String accountUrl) {
        this.accountUrl = accountUrl;
    }

    public void setAccountUrlWithReferrer(String accountUrlWithReferrer) {
        this.accountUrlWithReferrer = accountUrlWithReferrer;
    }

    public Optional<String> accountUrlWithReferrer() {
        return Optional.ofNullable(accountUrlWithReferrer);
    }

    public static class DataKey<T> {
        private Class<T> type;
        private String identifier;

        public DataKey(String identifier, Class<T> type) {
            this.identifier = identifier;
            this.type = type;
        }

        public boolean typeMatch(T t) {
            return type.isInstance(t);
        }

        public Optional<T> cast(Object o) {
            if (type.isInstance(o)) {
                return Optional.of(type.cast(o));
            } else {
                return Optional.empty();
            }
        }
    }
}
