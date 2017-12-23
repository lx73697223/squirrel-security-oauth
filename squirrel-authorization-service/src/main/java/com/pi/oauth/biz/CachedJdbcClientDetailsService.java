package com.pi.oauth.biz;

import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;

@Service
public class CachedJdbcClientDetailsService extends JdbcClientDetailsService {

    public CachedJdbcClientDetailsService(DataSource dataSource) {
        super(dataSource);
    }

    // @Cacheable(cacheManager = "guavaCacheManager", value = "OAUTH_CLIENT_DETAILS")
    @Override
    public ClientDetails loadClientByClientId(String clientId) throws InvalidClientException {
        return super.loadClientByClientId(clientId);
    }
}
