package com.pi.oauth.resource.authentication;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.pi.oauth.dto.MutableUserDetails;
import com.pi.oauth.resource.token.IdTokenConverter;
import com.pi.oauth.resource.token.JwtTokenAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Collection;
import java.util.Collections;

public class IdTokenAuthenticationProvider implements AuthenticationProvider {

    private RSAPublicKey publicKey;

    private IdTokenConverter idTokenConverter;

    private UserPermissionProvider userPermissionProvider;

    public void setPublicKey(RSAPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public void setIdTokenConverter(IdTokenConverter idTokenConverter) {
        this.idTokenConverter = idTokenConverter;
    }

    public void setUserPermissionProvider(UserPermissionProvider userPermissionProvider) {
        this.userPermissionProvider = userPermissionProvider;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {
            SignedJWT jwt = SignedJWT.parse(String.valueOf(authentication.getPrincipal()));
            if (!jwt.getHeader().getCriticalParams().contains("tty")) {
                return null;
            }

            if (!"id_token".equals(jwt.getHeader().getCustomParam("tty"))) {
                return null;
            }

            if (!jwt.verify(new RSASSAVerifier(publicKey, jwt.getHeader().getCriticalParams()))) {
                throw new InvalidTokenException("Invalid id token");
            }

            if (jwt.getJWTClaimsSet().getExpirationTime() == null
                    || System.currentTimeMillis() > jwt.getJWTClaimsSet().getExpirationTime().getTime()) {
                throw new InvalidTokenException("Expired id token");
            }

            MutableUserDetails userDetails = idTokenConverter.convert(jwt.getJWTClaimsSet());

            Collection<? extends GrantedAuthority> authorities = userPermissionProvider != null
                    ? userPermissionProvider.findGrantedAuthoritiesByUserIdentifier(userDetails.getUsername())
                    : Collections.emptyList();
            if (authorities == null) {
                authorities = Collections.emptyList();
            }
            userDetails.setAuthorities(authorities);

            return new UsernamePasswordAuthenticationToken(userDetails, "N/A", authorities);

        } catch (ParseException | JOSEException e) {
            throw new InvalidTokenException("Invalid id token", e);
        }
    }
}
