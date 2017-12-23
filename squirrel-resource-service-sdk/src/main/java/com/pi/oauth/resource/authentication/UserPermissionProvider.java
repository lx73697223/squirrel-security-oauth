package com.pi.oauth.resource.authentication;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public interface UserPermissionProvider {

    Collection<? extends GrantedAuthority> findGrantedAuthoritiesByUserIdentifier(String userIdentifier);
}
