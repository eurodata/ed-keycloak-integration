/*
 * Eurodata AG
 *
 * Copyright 2018 cbuerckert.
 */
package de.eurodata.keycloak.boot;

import de.eurodata.keycloak.util.Authenticator;
import de.eurodata.keycloak.util.AuthenticatorFactory;
import de.eurodata.keycloak.util.dto.EdAuthHeader;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.methods.HttpUriRequest;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.springsecurity.AdapterDeploymentContextFactoryBean;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationEntryPoint;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.authentication.KeycloakLogoutHandler;
import org.keycloak.adapters.springsecurity.client.KeycloakClientRequestFactory;
import org.keycloak.adapters.springsecurity.client.KeycloakRestTemplate;
import org.keycloak.adapters.springsecurity.filter.*;
import org.keycloak.adapters.springsecurity.management.HttpSessionManager;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.annotation.RequestScope;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.security.Principal;
import java.util.Optional;

@Slf4j
public class EurodataKeycloakSecurityConfig extends WebSecurityConfigurerAdapter implements WebSecurityConfigurer<WebSecurity> {

    public EurodataKeycloakSecurityConfig() {
        //Auch @async methoden sollen etwas von keycloak haben.
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }

    /**
     * Use Keycloak configuration from properties / yaml. Nicht die
     * keycloak.json.
     *
     * @return
     */
    @Bean
    public KeycloakConfigResolver keycloakConfigResolver() {
        return new KeycloakConfigResolver() {

            @Autowired
            AdapterConfig keycloakConfig;

            private KeycloakDeployment keycloakDeployment;

            @Override
            public KeycloakDeployment resolve(HttpFacade.Request request) {
                if (keycloakDeployment != null) {
                    return keycloakDeployment;
                }

                keycloakDeployment = KeycloakDeploymentBuilder.build(keycloakConfig);

                return keycloakDeployment;
            }
        };
    }

    @Bean
    protected AdapterDeploymentContextFactoryBean adapterDeploymentContext() throws Exception {
        AdapterDeploymentContextFactoryBean factoryBean;
        factoryBean = new AdapterDeploymentContextFactoryBean(keycloakConfigResolver());
        factoryBean.afterPropertiesSet();
        return factoryBean;
    }

    protected AuthenticationEntryPoint authenticationEntryPoint() throws Exception {
        return new KeycloakAuthenticationEntryPoint(adapterDeploymentContext().getObject());
    }

    protected KeycloakAuthenticationProvider keycloakAuthenticationProvider() {
        return new KeycloakAuthenticationProvider();
    }

    @Bean
    protected KeycloakAuthenticationProcessingFilter keycloakAuthenticationProcessingFilter() throws Exception {
        KeycloakAuthenticationProcessingFilter filter = new KeycloakAuthenticationProcessingFilter(authenticationManagerBean());
        filter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy());
        return filter;
    }

    @Bean
    protected KeycloakPreAuthActionsFilter keycloakPreAuthActionsFilter() {
        return new KeycloakPreAuthActionsFilter(httpSessionManager());
    }

    protected KeycloakCsrfRequestMatcher keycloakCsrfRequestMatcher() {
        return new KeycloakCsrfRequestMatcher();
    }

    @Bean
    protected HttpSessionManager httpSessionManager() {
        return new HttpSessionManager();
    }

    protected KeycloakLogoutHandler keycloakLogoutHandler() throws Exception {
        return new KeycloakLogoutHandler(adapterDeploymentContext().getObject());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().requireCsrfProtectionMatcher(keycloakCsrfRequestMatcher())
                .and()
                .sessionManagement()
                .sessionAuthenticationStrategy(sessionAuthenticationStrategy())
                .and()
                .addFilterBefore(keycloakPreAuthActionsFilter(), LogoutFilter.class)
                .addFilterBefore(keycloakAuthenticationProcessingFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(keycloakSecurityContextRequestFilter(), SecurityContextHolderAwareRequestFilter.class)
                .addFilterAfter(keycloakAuthenticatedActionsRequestFilter(), KeycloakSecurityContextRequestFilter.class)
                .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint())
                .and()
                .logout()
                .addLogoutHandler(keycloakLogoutHandler())
                .logoutUrl("/sso/logout").permitAll()
                .logoutSuccessUrl("/");

        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .sessionAuthenticationStrategy(sessionAuthenticationStrategy());

        http.addFilterBefore(new SecretTokenAccessFilter(authenticationManager()), BasicAuthenticationFilter.class);
    }

    @Bean
    protected KeycloakSecurityContextRequestFilter keycloakSecurityContextRequestFilter() {
        return new KeycloakSecurityContextRequestFilter();
    }

    @Bean
    protected KeycloakAuthenticatedActionsFilter keycloakAuthenticatedActionsRequestFilter() {
        return new KeycloakAuthenticatedActionsFilter();
    }

    /**
     * Desired to overwrite.
     *
     * @return
     */
    protected EurodataAccountService getAccountService() {
        return null;
    }

    /**
     * Rollen von Keycloak in Spring Boot Mappen. Provider registrieren. Den
     * SecretTokenProvider nicht vergessen.
     *
     * @param authManagerBuilder
     * @param secretTokenAuthProvider
     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder authManagerBuilder, SecretTokenAuthenticationProvider secretTokenAuthProvider) {
        EurodataKeycloakAuthenticationProvider keycloakProvider = new EurodataKeycloakAuthenticationProvider(this::getAccountService);
        authManagerBuilder
                .authenticationProvider(keycloakProvider)
                .authenticationProvider(secretTokenAuthProvider);
    }

    /**
     * Secret Token Service starten.
     *
     * @return
     */
    @Bean
    public SecretTokenService secretTokenService() {
        return new SecretTokenServiceImpl();
    }

    @Bean
    public SecretTokenAuthenticationProvider secretTokenAuthenticationProvider(@Autowired SecretTokenService tokenService) {
        return new SecretTokenAuthenticationProvider(tokenService, this::getAccountService);
    }

    @Bean
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new NullAuthenticatedSessionStrategy();
    }

    /**
     * Returns the {@link KeycloakSecurityContext} from the Spring
     * {@link ServletRequestAttributes}'s {@link Principal}.
     * <p>
     * The principal must support retrieval of the KeycloakSecurityContext, so
     * at this point, only {@link KeycloakPrincipal} values and
     * {@link KeycloakAuthenticationToken} are supported.
     *
     * @return the current <code>KeycloakSecurityContext</code>
     */
    @Bean
    @Scope(scopeName = WebApplicationContext.SCOPE_REQUEST, proxyMode = ScopedProxyMode.TARGET_CLASS)
    public KeycloakSecurityContext getKeycloakSecurityContext() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        Principal principal = attributes.getRequest().getUserPrincipal();
        if (principal == null) {
            return null;
        }
        if (principal instanceof KeycloakAuthenticationToken) {
            principal = (Principal) ((KeycloakAuthenticationToken) principal).getPrincipal();
        }
        if (principal instanceof KeycloakPrincipal) {
            return ((KeycloakPrincipal) principal).getKeycloakSecurityContext();
        }
        return null;
    }

    /**
     * {@link KeycloakRestTemplate} configured to use {@link AccessToken} of
     * current user.
     *
     * @return
     */
    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public KeycloakRestTemplate restTemplateCurrentUser() {
        return new KeycloakRestTemplate(new KeycloakClientRequestFactory());
    }

    /**
     * {@link RestTemplateCurrentServer} configured to use {@link AccessToken}
     * of current server.
     *
     * @param config
     * @return
     */
    @Bean
    public RestTemplateCurrentServer restTemplateCurrentServer(AdapterConfig config) {
        Authenticator auth = AuthenticatorFactory.getDefault().createClientSecret(
                config.getAuthServerUrl(),
                config.getRealm(),
                config.getResource(),
                String.valueOf(config.getCredentials().get("secret"))
        );

        //inject header into rest template
        return new RestTemplateCurrentServer(new HttpComponentsClientHttpRequestFactory() {
            @Override
            protected void postProcessHttpRequest(HttpUriRequest request) {
                EdAuthHeader header = auth.getHeader();
                request.setHeader(header.getKey(), header.getValue());
            }
        });
    }

    @Bean
    @RequestScope
    public EurodataAccount eurodataAccount(HttpServletRequest currentRequest) {
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();

        EurodataAccountService accountService = getAccountService();
        if (accountService == null) {
            return null;
        }

        if (currentAuth instanceof KeycloakAuthenticationToken) {
            KeycloakAuthenticationToken authToken = (KeycloakAuthenticationToken) currentAuth;

            RefreshableKeycloakSecurityContext keycloakSecurityContext = (RefreshableKeycloakSecurityContext) authToken.getCredentials();
            IDToken idToken = keycloakSecurityContext.getIdToken();

            if (idToken != null) {
                String accountUrl = KeycloakUriBuilder.fromUri(keycloakSecurityContext.getDeployment().getAccountUrl()).toTemplate();
                String accountUrlWithReferrer = KeycloakUriBuilder.fromUri(keycloakSecurityContext.getDeployment().getAccountUrl()) //
                        .queryParam("referrer", keycloakSecurityContext.getDeployment().getResourceName()) //
                        .queryParam("referrer_uri", getContextRootUri(currentRequest) + "/ui/") //
                        .toTemplate();


                EurodataAccount account = new EurodataAccount(authToken.getName(), authToken.getAuthorities());

                account.setUsername(idToken.getPreferredUsername());
                account.setSalutation(getAttributeFromIdToken(idToken, "salutation", "Herr/Frau"));
                account.setTitle(getAttributeFromIdToken(idToken, "title", ""));
                account.setFirstname(idToken.getGivenName());
                account.setLastname(idToken.getName());
                account.setEmail(idToken.getEmail());
                account.setAccountUrl(accountUrl);
                account.setAccountUrlWithReferrer(accountUrlWithReferrer);
                account.setDisplayName(idToken.getName());
                accountService.onLogin(currentRequest, account);
                return account;
            }

            AccessToken accessToken = keycloakSecurityContext.getToken();
            EurodataAccount account = new EurodataAccount(authToken.getName(), authToken.getAuthorities());

            account.setUsername(accessToken.getPreferredUsername());
            account.setSalutation(getAttributeFromIdToken(accessToken, "salutation", "Herr/Frau"));
            account.setTitle(getAttributeFromIdToken(accessToken, "title", ""));
            account.setFirstname(accessToken.getGivenName());
            account.setLastname(accessToken.getFamilyName());
            account.setDisplayName(accessToken.getName());
            account.setEmail(accessToken.getEmail());
            accountService.onLogin(currentRequest, account);
            return account;
        }
        if (currentAuth instanceof SecretToken) {
            SecretToken authToken = (SecretToken) currentAuth;
            EurodataAccount account = new EurodataAccount(authToken.getName(), authToken.getAuthorities());

            account.setUsername(authToken.getAccountInfo().getUsername());
            account.setSalutation(authToken.getAccountInfo().getSalutation());
            account.setTitle(authToken.getAccountInfo().getTitle());
            account.setFirstname(authToken.getAccountInfo().getFirstName());
            account.setLastname(authToken.getAccountInfo().getLastName());
            account.setDisplayName(authToken.getAccountInfo().getName());
            account.setEmail(authToken.getAccountInfo().getEmail());
            accountService.onLogin(currentRequest, account);
            return account;
        }

        return null;
    }

    String getAttributeFromIdToken(IDToken idToken, String attributeName, String defaultValue) {
        if (idToken.getOtherClaims() == null) {
            return defaultValue;
        }
        return Optional.ofNullable((String) idToken.getOtherClaims().get(attributeName)).orElse(defaultValue);
    }

    private String getContextRootUri(HttpServletRequest request) {
        return URI.create(request.getRequestURL().toString()).resolve(request.getContextPath()).toString();
    }

}
