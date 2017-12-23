package com.pi.oauth.authentication;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.pi.oauth.token.JwtBearerAssertionAuthenticationToken;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

public abstract class JwtBearerAssertionAuthenticationManager implements AuthenticationManager {

    private ClientDetailsService clientDetailsService;

    private KeyStoreKeyFactory keyStoreKeyFactory;

    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public void setKeyStoreKeyFactory(KeyStoreKeyFactory keyStoreKeyFactory) {
        this.keyStoreKeyFactory = keyStoreKeyFactory;
    }

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {

        JwtBearerAssertionAuthenticationToken authenticationToken = (JwtBearerAssertionAuthenticationToken) authentication;

        String clientId = authenticationToken.getClientId();
        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);

        SignedJWT jwt = authenticationToken.getJwt();
        try {
            if (!jwt.verify(createClientSignatureVerifier(clientDetails))) {
                throw handleAssertionValidationFailure("invalid authentication");
            }
        } catch (JOSEException e) {
            throw handleAssertionValidationFailure("invalid authentication");
        }

        String errorDescription = validateAssertionClaims(authenticationToken.getJwtClaims());
        if (StringUtils.isNotEmpty(errorDescription)) {
            throw handleAssertionValidationFailure(errorDescription);
        }

        return new JwtBearerAssertionAuthenticationToken(authenticationToken,
                                                         clientDetails.getAuthorities());
    }

    private JWSVerifier createClientSignatureVerifier(ClientDetails clientDetails) {
        KeyPair keyPair = keyStoreKeyFactory.getKeyPair(clientDetails.getClientId(),
                                                        clientDetails.getClientSecret()
                                                                     .toCharArray());
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        return new RSASSAVerifier(publicKey);
    }

    private String validateAssertionClaims(JWTClaimsSet jwtClaims) {
        // check the issuer
        if (StringUtils.isBlank(jwtClaims.getIssuer())) {
            return "issuer is required";
        }

        // check subject
        if (StringUtils.isBlank(jwtClaims.getSubject())) {
            return "subject is required";
        }

        // check expiration
        if (jwtClaims.getExpirationTime() == null) {
            return "expiration is required";
        } else {
            // it's not null, see if it's expired
            Date now = new Date(System.currentTimeMillis());
            if (now.after(jwtClaims.getExpirationTime())) {
                return "authentication has expired";
            }
        }

        // check not before
        if (jwtClaims.getNotBeforeTime() != null) {
            Date now = new Date(System.currentTimeMillis() + 5000);
            if (now.before(jwtClaims.getNotBeforeTime())) {
                return "authentication is not valid yet";
            }
        }

        // check issued at
        if (jwtClaims.getIssueTime() != null) {
            // since it's not null, see if it was issued in the future
            Date now = new Date(System.currentTimeMillis() + 5000);
            if (now.before(jwtClaims.getIssueTime())) {
                return "authentication was issued in the future";
            }
        }

        // check audience
        if (jwtClaims.getAudience() == null) {
            return "audience is required";
        }

        // TODO: Check audience

        return postAssertionClaimsValidation(jwtClaims);
    }

    /**
     @param jwtClaims
     */
    protected String postAssertionClaimsValidation(JWTClaimsSet jwtClaims) {
        return null;
    }

    public abstract OAuth2Exception handleAssertionValidationFailure(String errorMessage);

}
