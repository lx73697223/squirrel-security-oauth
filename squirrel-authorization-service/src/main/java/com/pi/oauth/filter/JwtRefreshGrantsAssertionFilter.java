package com.pi.oauth.filter;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;

public class JwtRefreshGrantsAssertionFilter extends JwtBearerAssertionFilter {

    public static final String GRANT_TYPE = "refresh_token";

    public JwtRefreshGrantsAssertionFilter() {
        super(new AuthorizationGrantsAssertionRequestMatcher());
    }

    @Override
    protected String extractToken(HttpServletRequest request) {
        return request.getParameter("authentication");
    }

    private static class AuthorizationGrantsAssertionRequestMatcher implements RequestMatcher {

        @Override
        public boolean matches(HttpServletRequest request) {
            // check for appropriate parameters
            String grantType = request.getParameter("grant_type");
            String assertion = request.getParameter("authentication");

            return GRANT_TYPE.equals(grantType) && StringUtils.isNotEmpty(assertion);
        }
    }
}
