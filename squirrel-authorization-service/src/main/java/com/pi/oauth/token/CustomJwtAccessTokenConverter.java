package com.pi.oauth.token;

import com.google.common.collect.Sets;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.pi.oauth.configuration.OAuthServerProperties;
import com.pi.oauth.dto.UserDetailsDto;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
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

    private OAuthServerProperties oauthServerProperties;

    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public void setKeyStoreKeyFactory(KeyStoreKeyFactory keyStoreKeyFactory) {
        this.keyStoreKeyFactory = keyStoreKeyFactory;
    }

    public void setOAuthServerProperties(OAuthServerProperties oauthServerProperties) {
        this.oauthServerProperties = oauthServerProperties;
    }

    @Override
    protected String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {

        JWSHeader.Builder headBulider = new JWSHeader.Builder(JWSAlgorithm.RS256);
        if (!accessToken.getAdditionalInformation().containsKey(ACCESS_TOKEN_ID)) {
            headBulider.criticalParams(Sets.newHashSet("tty")).customParam("tty", "access_token");
        }
        JWSHeader header = headBulider.build();

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder().issuer("issuer");
        OAuth2Request clientToken = authentication.getOAuth2Request();
        Set<String> scope = accessToken.getScope();

        if (!authentication.isClientOnly()) {
            UserDetailsDto user = (UserDetailsDto) authentication.getPrincipal();
            builder.subject(user.getId());
            builder.claim(UserAuthenticationConverter.USERNAME, user.getUsername());
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

        clientDetailsService.loadClientByClientId(clientToken.getClientId());

        JWTClaimsSet claimsSet = builder.build();
        SignedJWT jwt = new SignedJWT(header, claimsSet);
        try {
            KeyPair keyPair = keyStoreKeyFactory.getKeyPair(oauthServerProperties.getKeyAlias(),
                    oauthServerProperties.getKeyPassword().toCharArray());
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
            JWTClaimsSet jwtClaims = jwt.getJWTClaimsSet();
            clientDetailsService.loadClientByClientId(jwtClaims.getStringClaim(CLIENT_ID));

            KeyPair keyPair = keyStoreKeyFactory.getKeyPair(oauthServerProperties.getKeyAlias(),
                    oauthServerProperties.getKeyPassword().toCharArray());

            if (jwt.verify(new RSASSAVerifier((RSAPublicKey) keyPair.getPublic(), jwt.getHeader().getCriticalParams()))) {
                return jwtClaims.toJSONObject();
            } else {
                throw new InvalidTokenException("Invalid access token");
            }
        } catch (ParseException | JOSEException e) {
            throw new InvalidTokenException("Invalid access token", e);
        }
    }
}
