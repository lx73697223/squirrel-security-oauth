package com.pi.oauth.endpoint;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginEndpoint {

    @GetMapping("/login")
    public String hi() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return "hi~ " + authentication.toString();
    }

    @GetMapping("/t")
    public String t() {
        return "t~ ";
    }

}
