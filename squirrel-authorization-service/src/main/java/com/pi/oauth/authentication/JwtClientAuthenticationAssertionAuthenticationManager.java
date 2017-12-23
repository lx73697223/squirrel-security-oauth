package com.pi.oauth.authentication;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

import java.util.Objects;

public class JwtClientAuthenticationAssertionAuthenticationManager extends
        JwtBearerAssertionAuthenticationManager {

    @Override
    protected String postAssertionClaimsValidation(JWTClaimsSet jwtClaims) {
        String error = super.postAssertionClaimsValidation(jwtClaims);
        if (StringUtils.isNotEmpty(error)) {
            return error;
        }

        if (!Objects.equals(jwtClaims.getIssuer(), jwtClaims.getSubject())) {
            return "issuer does not equal to subject";
        }

        return null;
    }

    @Override
    public OAuth2Exception handleAssertionValidationFailure(String errorMessage) {
        return new InvalidClientException(errorMessage);
    }
}
