package com.pi.oauth.resource.dto;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Data
public class UserDetailsDto implements MutableUserDetails {

    private Collection<? extends GrantedAuthority> authorities;

    private String password;

    private String username;

    private String phone;

    private String id;

    private boolean accountNonExpired;

    private boolean accountNonLocked;

    private boolean credentialsNonExpired;

    private boolean enabled;

}
