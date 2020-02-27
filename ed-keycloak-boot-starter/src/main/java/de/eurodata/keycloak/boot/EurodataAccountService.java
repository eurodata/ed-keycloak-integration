package de.eurodata.keycloak.boot;

import org.springframework.security.core.AuthenticationException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Set;

public interface EurodataAccountService {

    /**
     * Return the GrantedAuthorities for this account. A set of predefined authorities is given
     *
     * @param accountId             - given account identifier
     * @param predefinedAuthorities - given authorities from jwt or secret token
     * @return - final results after checking the database
     * @throws AuthenticationException - if you want to disallow this user
     */
    Set<EurodataAuthority> loadAccountAuthorities(String accountId, Set<String> predefinedAuthorities);


    /**
     * Handle Account Login - for instance update your database.
     *
     * @param request
     * @param account
     * @throws AuthenticationException - if you want to disallow this user
     */
    void onLogin(HttpServletRequest request, EurodataAccount account);

}
