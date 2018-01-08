package com.pi.oauth.resource.token;

import com.google.common.collect.Sets;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.pi.oauth.resource.dto.UserDetailsDto;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class CustomJwtAccessTokenConverter extends JwtAccessTokenConverter {

    private ClientDetailsService clientDetailsService;

    private KeyStoreKeyFactory keyStoreKeyFactory;

    private RSAPublicKey publicKey;

    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public void setKeyStoreKeyFactory(KeyStoreKeyFactory keyStoreKeyFactory) {
        this.keyStoreKeyFactory = keyStoreKeyFactory;
    }

    public void setPublicKey(RSAPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    protected String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {

        OAuth2Request clientToken = authentication.getOAuth2Request();

        JWSHeader.Builder headBulider = new JWSHeader.Builder(JWSAlgorithm.RS256);
        if (!accessToken.getAdditionalInformation().containsKey(ACCESS_TOKEN_ID)) {
            headBulider.criticalParams(Sets.newHashSet("tty")).customParam("tty", "access_token");
        }
        JWSHeader header = headBulider.build();

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder().issuer("issuer");

        Set<String> scope = accessToken.getScope();
        if (!authentication.isClientOnly()) {
            UserDetailsDto userDetails = (UserDetailsDto) authentication.getPrincipal();
            if (StringUtils.isNotBlank(userDetails.getId())) {
                builder.subject(userDetails.getId());
            } else {
                builder.subject(userDetails.getUsername());
            }
            if (authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty()) {
                builder.claim(AUTHORITIES, AuthorityUtils.authorityListToSet(authentication.getAuthorities()));
            }
            if (scope == null) {
                scope = new HashSet<>(2);
            } else {
                scope = new HashSet<>(accessToken.getScope());
            }
            scope.add("openid");
        } else {
            if (clientToken.getAuthorities() != null && !clientToken.getAuthorities().isEmpty()) {
                builder.claim(UserAuthenticationConverter.AUTHORITIES,
                              AuthorityUtils.authorityListToSet(clientToken.getAuthorities()));
            }
        }
        if (accessToken.getScope() != null) {
            builder.claim(SCOPE, scope);
        }

        if (accessToken.getExpiration() != null) {
            builder.expirationTime(accessToken.getExpiration());
        }

        if (authentication.getOAuth2Request().getGrantType() != null) {
            builder.claim(GRANT_TYPE, authentication.getOAuth2Request().getGrantType());
        }

        Map<String, Object> map = accessToken.getAdditionalInformation();
        if (map != null) {
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                builder.claim(entry.getKey(), entry.getValue());
            }
        }

        builder.claim(CLIENT_ID, clientToken.getClientId());
        if (clientToken.getResourceIds() != null && !clientToken.getResourceIds().isEmpty()) {
            builder.audience(new ArrayList<>(clientToken.getResourceIds()));
        }

        JWTClaimsSet claimsSet = builder.build();
        SignedJWT jwt = new SignedJWT(header, claimsSet);
        try {
            ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientToken.getClientId());
            KeyPair keyPair = keyStoreKeyFactory.getKeyPair(clientDetails.getClientId(),
                    clientDetails.getClientSecret().toCharArray());
            jwt.sign(new RSASSASigner(keyPair.getPrivate()));
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return jwt.serialize();
    }

    @Override
    protected Map<String, Object> decode(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            if (jwt.verify(new RSASSAVerifier(publicKey, jwt.getHeader().getCriticalParams()))) {
                return jwt.getJWTClaimsSet().toJSONObject();
            } else {
                throw new InvalidTokenException("Invalid access token");
            }
        } catch (ParseException | JOSEException e) {
            throw new InvalidTokenException("Invalid access token", e);
        }
    }
}
