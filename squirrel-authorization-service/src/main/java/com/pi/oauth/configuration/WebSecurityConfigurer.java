package com.pi.oauth.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
@Configuration
public class WebSecurityConfigurer extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity configurer) throws Exception {
        // @formatter:off
        configurer.requestMatchers().anyRequest().and().authorizeRequests()
                  .antMatchers("/oauth/*", "/login").permitAll();
        // @formatter:on
    }

}
