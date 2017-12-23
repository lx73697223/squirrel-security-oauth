package com.pi.oauth.resource.configuration;

import com.pi.common.utils.core.IteratorUtils;
import com.pi.oauth.resource.authentication.AccessTokenAuthenticationProvider;
import com.pi.oauth.resource.authentication.IdTokenAuthenticationProvider;
import com.pi.oauth.resource.authentication.UserPermissionProvider;
import com.pi.oauth.resource.token.CustomJwtAccessTokenConverter;
import com.pi.oauth.resource.token.IdTokenConverter;
import com.pi.oauth.resource.token.JwtBearTokenExtractor;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ResourceLoaderAware;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

@EnableResourceServer
@Configuration
// this is to turn on spring's security annotation like PreAuthorize, etc.
@EnableGlobalMethodSecurity(prePostEnabled = true)
@ConditionalOnProperty(prefix = "pi.oauth.resource", name = "cert-location")
@EnableConfigurationProperties(OAuthResourceProperties.class)
public class ResourceServerConfigurer extends ResourceServerConfigurerAdapter
        implements ResourceLoaderAware, InitializingBean {

    private static final String RESOURCE_ID = "oauth2-resource";

    @Autowired(required = false)
    private IdTokenConverter idTokenConverter;

    @Autowired(required = false)
    @Qualifier("userPermissionProvider")
    private UserPermissionProvider userPermissionProvider;

    @Autowired
    private OAuthResourceProperties oauthResourceProperties;

    private RSAPublicKey publicKey;

    private ResourceLoader resourceLoader;

    @Override
    public void setResourceLoader(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Resource resource = resourceLoader.getResource(oauthResourceProperties.getCertLocation());
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        try (InputStream input = resource.getInputStream()) {
            Certificate certificate = certificateFactory.generateCertificate(input);
            this.publicKey = (RSAPublicKey) certificate.getPublicKey();
        }
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer configurer) throws Exception {

        CustomJwtAccessTokenConverter tokenConverter = new CustomJwtAccessTokenConverter();
        tokenConverter.setPublicKey(publicKey);

        TokenStore tokenStore = new JwtTokenStore(tokenConverter);
        List<AuthenticationProvider> authenticationProviders = new ArrayList<>(2);
        authenticationProviders.add(accessTokenAuthenticationProvider(tokenStore));
        if (idTokenConverter != null) {
            authenticationProviders.add(idTokenAuthenticationProvider());
        }
        ProviderManager providerManager = new ProviderManager(authenticationProviders);
        configurer.resourceId(RESOURCE_ID).tokenStore(tokenStore).tokenExtractor(new JwtBearTokenExtractor())
                  .authenticationManager(providerManager);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        List<String> excludePaths = oauthResourceProperties.getExcludePaths();
        if (IteratorUtils.isEmpty(excludePaths)) {
            http.authorizeRequests().anyRequest().authenticated();
        } else {
            String[] paths = new String[excludePaths.size()];
            http.authorizeRequests().antMatchers(excludePaths.toArray(paths)).permitAll()
                .anyRequest().authenticated();
        }
    }

    private AccessTokenAuthenticationProvider accessTokenAuthenticationProvider(TokenStore tokenStore) {
        AccessTokenAuthenticationProvider accessTokenAuthenticationProvider = new AccessTokenAuthenticationProvider();
        accessTokenAuthenticationProvider.setAuthenticationManager(oauthAuthenticationManager(tokenStore));
        return accessTokenAuthenticationProvider;
    }

    private OAuth2AuthenticationManager oauthAuthenticationManager(TokenStore tokenStore) {
        OAuth2AuthenticationManager oauthAuthenticationManager = new OAuth2AuthenticationManager();
        oauthAuthenticationManager.setResourceId(RESOURCE_ID);
        oauthAuthenticationManager.setTokenServices(tokenServices(tokenStore));
        return oauthAuthenticationManager;
    }

    private ResourceServerTokenServices tokenServices(TokenStore tokenStore) {
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setTokenStore(tokenStore);
        tokenServices.setSupportRefreshToken(true);
        return tokenServices;
    }

    private IdTokenAuthenticationProvider idTokenAuthenticationProvider() {
        IdTokenAuthenticationProvider idTokenAuthenticationProvider = new IdTokenAuthenticationProvider();
        idTokenAuthenticationProvider.setPublicKey(publicKey);
        idTokenAuthenticationProvider.setIdTokenConverter(idTokenConverter);
        idTokenAuthenticationProvider.setUserPermissionProvider(userPermissionProvider);
        return idTokenAuthenticationProvider;
    }

}
