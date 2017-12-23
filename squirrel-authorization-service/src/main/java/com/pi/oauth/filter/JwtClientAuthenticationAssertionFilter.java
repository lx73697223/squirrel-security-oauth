package com.pi.oauth.filter;

import com.pi.oauth.filter.JwtBearerAssertionFilter;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;

public class JwtClientAuthenticationAssertionFilter extends JwtBearerAssertionFilter {

    private static final String CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-authentication-type:jwt-bearer";

    public JwtClientAuthenticationAssertionFilter() {
        super(new ClientAuthenticationAssertionRequestMatcher());
    }

    @Override
    protected String extractToken(HttpServletRequest request) {
        return request.getParameter("client_assertion");
    }

    private static class ClientAuthenticationAssertionRequestMatcher implements RequestMatcher {

        @Override
        public boolean matches(HttpServletRequest request) {
            // check for appropriate parameters
            String assertionType = request.getParameter("client_assertion_type");
            String assertion = request.getParameter("client_assertion");

            return CLIENT_ASSERTION_TYPE.equals(assertionType) && StringUtils.isNotEmpty(assertion);
        }
    }
}
