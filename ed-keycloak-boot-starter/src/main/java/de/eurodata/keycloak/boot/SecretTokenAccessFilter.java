/*
 * Eurodata AG
 *
 * Copyright 2018 Eurodata AG.
 */
package de.eurodata.keycloak.boot;

import de.eurodata.keycloak.util.SecretTokenAuthenticator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * @author cbuerckert
 */
@Slf4j
public class SecretTokenAccessFilter extends GenericFilterBean {

    private AuthenticationManager authenticationManager;

    public SecretTokenAccessFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = asHttp(request);
        HttpServletResponse httpResponse = asHttp(response);

        Optional<String> tokenheader = Optional.ofNullable(httpRequest.getHeader(SecretTokenAuthenticator.HEADER_KEY));

        Optional<String> tokencookie = httpRequest.getCookies() != null ? Stream.of(httpRequest.getCookies())
                .filter(x -> x.getName().equals(SecretTokenAuthenticator.HEADER_KEY))
                .map(Cookie::getValue)
                .findAny() : Optional.empty();

        try {
            if (tokenheader.isPresent()) {
                log.info("Token - Trying to authenticate user by  method - Header: {} - IP: ", tokenheader, request.getRemoteHost());
                processTokenAuthentication(tokenheader.get());
            }
            if (tokencookie.isPresent()) {
                log.info("Cookie - Trying to authenticate user by  method - Cookie: {} - IP: ", tokencookie, request.getRemoteHost());
                processTokenAuthentication(tokencookie.get());
            }
            chain.doFilter(request, response);
        } catch (InternalAuthenticationServiceException internalAuthenticationServiceException) {
            SecurityContextHolder.clearContext();
            log.error("Internal authentication service exception", internalAuthenticationServiceException);
            httpResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        } catch (AuthenticationException authenticationException) {
            SecurityContextHolder.clearContext();
            if (tokencookie.isPresent() && !tokencookie.get().matches("NONE")) {
                //if cookie was present which resulted in authenticationException 
                //the cookie will be removed and the user will be redirected.
                Cookie cookie = Stream.of(httpRequest.getCookies())
                        .filter(x -> x.getName().equals(SecretTokenAuthenticator.HEADER_KEY))
                        .findAny().orElseThrow(NoSuchElementException::new);
                cookie.setValue("NONE");
                httpResponse.addCookie(cookie);
                //cookie is removed - user is redirected to /authcookie
                httpResponse.sendRedirect(httpRequest.getContextPath() + "/login");
                return;
            }
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, authenticationException.getMessage());
        }
    }

    private HttpServletRequest asHttp(ServletRequest request) {
        return (HttpServletRequest) request;
    }

    private HttpServletResponse asHttp(ServletResponse response) {
        return (HttpServletResponse) response;
    }

    private void processTokenAuthentication(String token) {
        Authentication resultOfAuthentication = tryToAuthenticateWithToken(token);
        SecurityContextHolder.getContext().setAuthentication(resultOfAuthentication);
    }

    private Authentication tryToAuthenticateWithToken(String token) {
        SecretToken requestAuthentication = new SecretToken(token, null, new SecretTokenAccountInfo(token));
        return tryToAuthenticate(requestAuthentication);
    }

    private Authentication tryToAuthenticate(Authentication requestAuthentication) {
        Authentication responseAuthentication = authenticationManager.authenticate(requestAuthentication);
        if (responseAuthentication == null || !responseAuthentication.isAuthenticated()) {
            log.warn("Illegal Token {}", responseAuthentication);
            throw new InternalAuthenticationServiceException("Unable to authenticate Domain User for provided credentials");
        }
        log.info("User successfully authenticated {}", responseAuthentication);
        return responseAuthentication;
    }
}
