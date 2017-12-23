package com.pi.oauth.resource.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "pi.oauth.resource")
@Data
public class OAuthResourceProperties {

    private String certLocation;

    private List<String> excludePaths;

}
