package com.pi.oauth.resource.token;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;

import javax.servlet.http.HttpServletRequest;

public class JwtBearTokenExtractor extends BearerTokenExtractor {

    @Override
    public Authentication extract(HttpServletRequest request) {
        Authentication authentication = super.extract(request);
        return authentication == null ? null : new JwtTokenAuthenticationToken(authentication.getPrincipal(), "");
    }
}
