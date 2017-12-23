package com.pi.oauth.dto;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public interface MutableUserDetails extends UserDetails {

    void setAuthorities(Collection<? extends GrantedAuthority> authorities);

}
