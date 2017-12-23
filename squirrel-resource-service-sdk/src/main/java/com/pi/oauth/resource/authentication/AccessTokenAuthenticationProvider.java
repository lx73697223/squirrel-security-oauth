package com.pi.oauth.resource.authentication;

import com.nimbusds.jwt.SignedJWT;
import com.pi.oauth.resource.token.JwtTokenAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;

import java.text.ParseException;

public class AccessTokenAuthenticationProvider implements AuthenticationProvider {

    private OAuth2AuthenticationManager authenticationManager;

    public void setAuthenticationManager(OAuth2AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {
            SignedJWT jwt = SignedJWT.parse(authentication.getPrincipal().toString());
            if (!jwt.getHeader().getCriticalParams().contains("tty")) {
                return null;
            }
            if (!"access_token".equals(jwt.getHeader().getCustomParam("tty"))) {
                return null;
            }

            return authenticationManager.authenticate(authentication);

        } catch (ParseException e) {
            throw new InvalidTokenException("Invalid access token", e);
        }
    }
}
