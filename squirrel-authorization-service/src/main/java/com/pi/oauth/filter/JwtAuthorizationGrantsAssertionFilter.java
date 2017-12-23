package com.pi.oauth.filter;

import com.pi.oauth.filter.JwtBearerAssertionFilter;
import com.pi.oauth.token.JwtAuthorizationGrantsAssertionTokenGranter;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;

public class JwtAuthorizationGrantsAssertionFilter extends JwtBearerAssertionFilter {

    public JwtAuthorizationGrantsAssertionFilter() {
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

            return JwtAuthorizationGrantsAssertionTokenGranter.GRANT_TYPE.equals(grantType) &&
                   StringUtils.isNotEmpty(assertion);
        }
    }
}
