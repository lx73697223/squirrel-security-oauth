package com.pi.oauth.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ResourceLoaderAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@Configuration
@EnableConfigurationProperties(OAuthServerProperties.class)
public class KeyStoreKeyFactoryConfiguration implements ResourceLoaderAware {

    @Autowired
    private OAuthServerProperties oauthServerProperties;

    private ResourceLoader resourceLoader;

    @Override
    public void setResourceLoader(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @Bean
    public KeyStoreKeyFactory keyStoreKeyFactory() {
        Resource resource = resourceLoader.getResource(
                oauthServerProperties.getKeyStoreLocation());
        char[] password = oauthServerProperties.getKeyStorePassword().toCharArray();
        return new KeyStoreKeyFactory(resource, password);
    }

}
