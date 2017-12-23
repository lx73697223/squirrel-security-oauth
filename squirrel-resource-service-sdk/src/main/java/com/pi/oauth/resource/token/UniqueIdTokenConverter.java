package com.pi.oauth.resource.token;

import com.nimbusds.jwt.JWTClaimsSet;
import com.pi.oauth.dto.MutableUserDetails;
import com.pi.oauth.dto.UserDetailsDto;
import org.springframework.stereotype.Component;

import java.text.ParseException;

@Component
public class UniqueIdTokenConverter implements IdTokenConverter {

    @Override
    public MutableUserDetails convert(JWTClaimsSet jwtClaims) throws ParseException {
        UserDetailsDto user = new UserDetailsDto();
        user.setId(jwtClaims.getSubject());
        user.setUsername(jwtClaims.getStringClaim("user_name"));
        user.setPhone(jwtClaims.getStringClaim("phone"));
        return user;
    }
}
