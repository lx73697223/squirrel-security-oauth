package com.pi.oauth.authentication;

import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

public class JwtRefreshGrantsAssertionAuthenticationManager
        extends JwtBearerAssertionAuthenticationManager {

    @Override
    public OAuth2Exception handleAssertionValidationFailure(String errorMessage) {
        return new InvalidGrantException(errorMessage);
    }
}
