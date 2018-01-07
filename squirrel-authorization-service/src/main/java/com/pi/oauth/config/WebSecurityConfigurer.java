package com.pi.oauth.config;

import com.pi.oauth.biz.UserDetailsManagementService;
import com.pi.oauth.constants.AuthServerConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

@EnableWebSecurity
@Configuration
public class WebSecurityConfigurer extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsManagementService userDetailsManagementService;

    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        return userDetailsManagementService;
    }

    @Override
    protected void configure(HttpSecurity configurer) throws Exception {
        // @formatter:off
        configurer.requestMatchers().anyRequest().and().authorizeRequests()
                  .antMatchers(AuthServerConstants.AUTH_API_URL + "/oauth/token", "/login")
                  .permitAll();
        // @formatter:on
    }

}
