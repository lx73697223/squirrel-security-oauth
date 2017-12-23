package com.pi.oauth.resource.token;

import com.nimbusds.jwt.JWTClaimsSet;
import com.pi.oauth.dto.MutableUserDetails;

import java.text.ParseException;

public interface IdTokenConverter {

    MutableUserDetails convert(JWTClaimsSet jwtClaims) throws ParseException;

}
