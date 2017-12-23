package com.pi.oauth.token;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.text.ParseException;
import java.util.Collection;

public class JwtBearerAssertionAuthenticationToken extends AbstractAuthenticationToken {

    private SignedJWT jwt;

    private JWTClaimsSet jwtClaims;

    private String clientId;

    private String subject;

    public JwtBearerAssertionAuthenticationToken(SignedJWT jwt) throws ParseException {
        super(null);
        setJwt(jwt);
        this.clientId = jwtClaims.getIssuer();
        this.subject = jwtClaims.getSubject();
        setAuthenticated(false);
    }

    public JwtBearerAssertionAuthenticationToken(JwtBearerAssertionAuthenticationToken token,
                                                 Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.clientId = token.clientId;
        this.subject = token.subject;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return jwt;
    }

    @Override
    public Object getPrincipal() {
        return clientId;
    }

    public SignedJWT getJwt() {
        return jwt;
    }

    public void setJwt(SignedJWT jwt) throws ParseException {
        this.jwt = jwt;
        this.jwtClaims = jwt == null ? null : jwt.getJWTClaimsSet();
    }

    public JWTClaimsSet getJwtClaims() {
        return jwtClaims;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getSubject() {
        return subject;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        try {
            setJwt(null);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

}
