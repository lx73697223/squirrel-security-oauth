package com.pi.oauth.filter;

import com.nimbusds.jwt.SignedJWT;
import com.pi.oauth.authentication.JwtBearerAssertionAuthenticationManager;
import com.pi.oauth.token.JwtBearerAssertionAuthenticationToken;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;

public abstract class JwtBearerAssertionFilter extends OncePerRequestFilter {

    private AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

    private JwtBearerAssertionAuthenticationManager authenticationManager;

    private RequestMatcher requiresAuthenticationRequestMatcher;

    public JwtBearerAssertionFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        this.requiresAuthenticationRequestMatcher = requiresAuthenticationRequestMatcher;
    }

    public void setAuthenticationManager(JwtBearerAssertionAuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void initFilterBean() throws ServletException {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.notNull(requiresAuthenticationRequestMatcher, "requiresAuthenticationRequestMatcher cannot be null");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!requiresAuthentication(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String token = extractToken(request);
            JwtBearerAssertionAuthenticationToken authentication = new JwtBearerAssertionAuthenticationToken(
                    SignedJWT.parse(token));

            Authentication authResult = authenticationManager.authenticate(authentication);

            SecurityContextHolder.getContext().setAuthentication(authResult);

        } catch (ParseException e) {

            OAuth2Exception failed = authenticationManager.handleAssertionValidationFailure("invalid authentication");
            handleException(request, response, failed);

        } catch (NoSuchClientException e) {

            InvalidClientException failed = new InvalidClientException("invalid client id");
            handleException(request, response, failed);

        } catch (OAuth2Exception failed) {
            handleException(request, response, failed);

        } catch (AuthenticationException failed) {
            handleException(request, response, failed);
        }

        filterChain.doFilter(request, response);
    }

    private boolean requiresAuthentication(HttpServletRequest request) {
        return requiresAuthenticationRequestMatcher.matches(request);
    }

    private void handleException(HttpServletRequest request, HttpServletResponse response, OAuth2Exception failed)
            throws IOException, ServletException {
        handleException(request, response, new InsufficientAuthenticationException(failed.getMessage(), failed));
    }

    private void handleException(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed)
            throws IOException, ServletException {

        SecurityContextHolder.clearContext();

        this.authenticationEntryPoint.commence(request, response, failed);
    }

    protected abstract String extractToken(HttpServletRequest request);

}
