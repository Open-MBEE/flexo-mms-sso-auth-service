package org.openmbee.flexo.mms.sso.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class JwtAuthController {

    @GetMapping("/jwt/info")
    public Map<String, Object> jwtInfo(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> info = new HashMap<>();
        System.out.println(jwt);
        info.put("sub", jwt.getSubject());
        info.put("iss", jwt.getIssuer().toString());
        info.put("exp", jwt.getExpiresAt().toString());
        info.put("claims", jwt.getClaims());

        return info;
    }
}