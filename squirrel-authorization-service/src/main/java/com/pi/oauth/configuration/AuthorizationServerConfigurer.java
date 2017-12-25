package com.pi.oauth.configuration;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestValidator;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import com.google.common.collect.Lists;
import com.pi.oauth.authentication.JwtAuthorizationGrantsAssertionAuthenticationManager;
import com.pi.oauth.authentication.JwtBearerAssertionAuthenticationManager;
import com.pi.oauth.authentication.JwtClientAuthenticationAssertionAuthenticationManager;
import com.pi.oauth.authentication.JwtRefreshGrantsAssertionAuthenticationManager;
import com.pi.oauth.filter.JwtAuthorizationGrantsAssertionFilter;
import com.pi.oauth.filter.JwtBearerAssertionFilter;
import com.pi.oauth.filter.JwtClientAuthenticationAssertionFilter;
import com.pi.oauth.filter.JwtRefreshGrantsAssertionFilter;
import com.pi.oauth.token.CustomJwtAccessTokenConverter;
import com.pi.oauth.token.IdTokenEnhancer;
import com.pi.oauth.token.JwtAuthorizationGrantsAssertionTokenGranter;

@EnableAuthorizationServer
@Configuration
@EnableConfigurationProperties(OAuthServerProperties.class)
public class AuthorizationServerConfigurer extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private ClientDetailsService clientDetailsService;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private KeyStoreKeyFactory keyStoreKeyFactory;

    @Autowired
    private OAuthServerProperties oauthServerProperties;

    /**
     * 配置(TokenEndpoint)的安全约束
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer configurer) throws Exception {

        // registerJwtClientAuthenticationAssertionFilter
        registerJwtBearerAssertionFilter(configurer, JwtClientAuthenticationAssertionAuthenticationManager::new,
                JwtClientAuthenticationAssertionFilter::new);

        // registerJwtAuthorizationGrantsAssertionFilter
        registerJwtBearerAssertionFilter(configurer, JwtAuthorizationGrantsAssertionAuthenticationManager::new,
                JwtAuthorizationGrantsAssertionFilter::new);

        // registerJwtRefreshGrantsAssertionFilter
        registerJwtBearerAssertionFilter(configurer, JwtRefreshGrantsAssertionAuthenticationManager::new,
                JwtRefreshGrantsAssertionFilter::new);

        configurer.checkTokenAccess("isAuthenticated()");

        // enable client to get the authenticated when using the /oauth/token to get a access token
        // there is a 401 authentication is required if it doesn't allow form authentication for clients when access /oauth/token
        configurer.allowFormAuthenticationForClients();
    }

    /**
     * 配置客户端详情服务（ClientDetailsService），客户端详情信息在这里进行初始化，
     * 把客户端详情信息写死在这里或者是通过数据库来存储调取详情信息
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer configurer) throws Exception {
        configurer.withClientDetails(clientDetailsService);
    }

    /**
     * 配置授权（authorization）以及令牌（token）的访问端点和令牌服务(token services)
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer configurer) throws Exception {

        TokenEnhancerChain tokenEnhancer = new TokenEnhancerChain();
        tokenEnhancer.setTokenEnhancers(Lists.newArrayList(jwtAccessTokenConverter(), idTokenEnhancer()));

        configurer.authenticationManager(authenticationManager()).accessTokenConverter(jwtAccessTokenConverter())
                .approvalStoreDisabled().tokenEnhancer(tokenEnhancer).reuseRefreshTokens(false)
                .userDetailsService(userDetailsService).requestValidator(new DefaultOAuth2RequestValidator());

        configureTokenGrant(configurer);
    }

    private IdTokenEnhancer idTokenEnhancer() {
        IdTokenEnhancer idTokenEnhancer = new IdTokenEnhancer();
        idTokenEnhancer.setKeyStoreKeyFactory(keyStoreKeyFactory);
        idTokenEnhancer.setOauth2Properties(oauthServerProperties);
        idTokenEnhancer.setClientDetailsService(clientDetailsService);
        return idTokenEnhancer;
    }

    private void configureTokenGrant(AuthorizationServerEndpointsConfigurer configurer) {

        JwtAuthorizationGrantsAssertionTokenGranter jwtAuthorizationGrantsAssertionTokenGranter = new JwtAuthorizationGrantsAssertionTokenGranter(
                configurer.getTokenServices(), configurer.getClientDetailsService(), configurer.getOAuth2RequestFactory());
        jwtAuthorizationGrantsAssertionTokenGranter.setUserDetailsService(userDetailsService);

        TokenGranter defaultTokenGranter = configurer.getTokenGranter();

        TokenGranter tokenGranter = new TokenGranter() {

            private CompositeTokenGranter delegate;

            @Override
            public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
                if (delegate == null) {
                    List<TokenGranter> tokenGranters = Lists.newArrayList(jwtAuthorizationGrantsAssertionTokenGranter,
                            defaultTokenGranter);
                    delegate = new CompositeTokenGranter(tokenGranters);
                }
                return delegate.grant(grantType, tokenRequest);
            }
        };
        configurer.tokenGranter(tokenGranter);
    }

    private void registerJwtBearerAssertionFilter(AuthorizationServerSecurityConfigurer configurer,
            Supplier<? extends JwtBearerAssertionAuthenticationManager> authenticationManagerSupplier,
            Supplier<? extends JwtBearerAssertionFilter> filterSupplier) {

        JwtBearerAssertionAuthenticationManager authenticationManager = authenticationManagerSupplier.get();
        authenticationManager.setKeyStoreKeyFactory(keyStoreKeyFactory);
        authenticationManager.setClientDetailsService(clientDetailsService);

        JwtBearerAssertionFilter filter = filterSupplier.get();
        filter.setAuthenticationManager(authenticationManager);

        configurer.addTokenEndpointAuthenticationFilter(filter);
    }

    /**
     * 认证管理器，密码（password）授权类型时需要
     */
    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);

        ProviderManager providerManager = new ProviderManager(Collections.singletonList(daoAuthenticationProvider));
        providerManager.setEraseCredentialsAfterAuthentication(true);
        return providerManager;
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() throws IOException, GeneralSecurityException {

        CustomJwtAccessTokenConverter tokenConverter = new CustomJwtAccessTokenConverter();
        tokenConverter.setClientDetailsService(clientDetailsService);
        tokenConverter.setKeyStoreKeyFactory(keyStoreKeyFactory);
        tokenConverter.setOAuthServerProperties(oauthServerProperties);
        return tokenConverter;
    }

}
