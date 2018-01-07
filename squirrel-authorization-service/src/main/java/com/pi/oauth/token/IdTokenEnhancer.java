package com.pi.oauth.token;

import com.google.common.collect.Sets;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.pi.oauth.config.OAuthServerProperties;
import com.pi.oauth.dto.UserDetailsDto;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.security.KeyPair;
import java.util.*;

public class IdTokenEnhancer implements TokenEnhancer {

    private ClientDetailsService clientDetailsService;

    private KeyStoreKeyFactory keyStoreKeyFactory;

    private OAuthServerProperties oauthServerProperties;

    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public void setKeyStoreKeyFactory(KeyStoreKeyFactory keyStoreKeyFactory) {
        this.keyStoreKeyFactory = keyStoreKeyFactory;
    }

    public void setOauth2Properties(OAuthServerProperties oauthServerProperties) {
        this.oauthServerProperties = oauthServerProperties;
    }

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken,
                                     OAuth2Authentication authentication) {

        if (authentication.isClientOnly()) {
            return accessToken;
        }

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).criticalParams(
                Sets.newHashSet("tty")).customParam("tty", "id_token").build();

        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(
                authentication.getOAuth2Request().getClientId());

        UserDetailsDto user = (UserDetailsDto) authentication.getPrincipal();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject(user.getId())
                .claim(UserAuthenticationConverter.USERNAME, user.getUsername())
                .claim("phone", user.getPhone())
                .claim("azp", clientDetails.getClientId())
                .claim(AccessTokenConverter.CLIENT_ID, clientDetails.getClientId())
                .expirationTime(new Date(System.currentTimeMillis() + (clientDetails.getAccessTokenValiditySeconds() * 1000L)))
                .build();

        SignedJWT jwt = new SignedJWT(header, claimsSet);
        try {
            KeyPair keyPair = keyStoreKeyFactory.getKeyPair(oauthServerProperties.getKeyAlias(),
                    oauthServerProperties.getKeyPassword().toCharArray());
            jwt.sign(new RSASSASigner(keyPair.getPrivate()));
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        DefaultOAuth2AccessToken result = new DefaultOAuth2AccessToken(accessToken);
        Map<String, Object> additionalInformation = new HashMap<>(result.getAdditionalInformation());
        additionalInformation.put("id_token", jwt.serialize());
        additionalInformation.put("refresh_token_expires_in", clientDetails.getRefreshTokenValiditySeconds());
        result.setAdditionalInformation(additionalInformation);

        Set<String> scope = result.getScope() == null ? new HashSet<>(2) : new HashSet<>(result.getScope());
        scope.add("openid");
        result.setScope(scope);

        return result;
    }

}
