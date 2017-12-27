package com.pi.oauth.resource.configuration;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;

@ConfigurationProperties(prefix = OAuthResourceProperties.PREFIX)
@Data
public class OAuthResourceProperties {

    public static final String PREFIX = "pi.oauth.resource";

    private String certLocation;

    private List<String> excludePaths;

}
