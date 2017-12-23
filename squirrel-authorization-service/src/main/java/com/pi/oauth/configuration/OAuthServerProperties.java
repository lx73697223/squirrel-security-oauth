package com.pi.oauth.configuration;

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
