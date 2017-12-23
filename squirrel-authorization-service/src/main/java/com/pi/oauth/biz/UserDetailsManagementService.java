package com.pi.oauth.biz;

import com.pi.oauth.dto.UserDetailsDto;
import com.pi.usercenter.endpoint.intf.UserAccountClient;
import com.pi.usercenter.endpoint.vo.UserAccountVo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class UserDetailsManagementService implements UserDetailsService {

    @Autowired
    @Qualifier("userAccountClient")
    private UserAccountClient userAccountClient;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserAccountVo userAccountVo = userAccountClient.getUserAccountByUsername(username);
        if (userAccountVo == null) {
            throw new UsernameNotFoundException("No userAccount with username: " + username);
        }

        UserDetailsDto userDetails = new UserDetailsDto();
        userDetails.setAuthorities(Collections.emptyList());
        userDetails.setAccountNonLocked(true);
        userDetails.setAccountNonExpired(true);
        userDetails.setCredentialsNonExpired(true);

        userDetails.setEnabled(userAccountVo.isDeleted());
        userDetails.setId(userAccountVo.getUniqueId());
        userDetails.setPassword(userAccountVo.getPassword());
        userDetails.setPhone(userAccountVo.getPhone());

        return userDetails;
    }
}
