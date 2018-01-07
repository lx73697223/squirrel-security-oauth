package com.pi.oauth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "pi.oauth.server")
@Data
public class OAuthServerProperties {

    private String keyAlias;

    private String keyPassword;

    private String keyStoreLocation;

    private String keyStorePassword;

}
