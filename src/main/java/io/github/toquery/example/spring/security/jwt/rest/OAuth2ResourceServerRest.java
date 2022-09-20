package io.github.toquery.example.spring.security.jwt.rest;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * OAuth2 Controller that access the JWT.
 */
@Slf4j
@RestController
public class OAuth2ResourceServerRest {

    @GetMapping("/")
    public String index(@AuthenticationPrincipal Jwt jwt, JwtAuthenticationToken authentication) {
        return String.format("Hello, %s and %s !", jwt.getSubject(), authentication.getName());
    }

    @GetMapping("/message")
    public String message() {
        return "secret message";
    }

}
