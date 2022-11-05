package com.example.cardatabase.web;

import com.example.cardatabase.domain.AccountCredentials;
//import com.example.cardatabase.service.JwtService;
import com.example.cardatabase.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
public class AuthController {
//    @Autowired
//    private JwtService jwtService;

    public static final Logger LOG = LoggerFactory.getLogger(AuthController.class);

    private final TokenService tokenService;

    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping("/token")
    public String token(Authentication authentication){
        LOG.debug("Token requested for user: '{}'", authentication.getName());
        String token = tokenService.generateToken(authentication);
        LOG.debug("Token returned: '{}'", token);
        return token;
    }

    @Autowired
    AuthenticationManager authenticationManager;

//    @RequestMapping(value="/login", method=RequestMethod.POST)
//    public ResponseEntity<?> getToken(@RequestBody AccountCredentials credentials) {
//        UsernamePasswordAuthenticationToken creds =
//                new UsernamePasswordAuthenticationToken(
//                        credentials.getUsername(),
//                        credentials.getPassword());
//
//        Authentication auth = authenticationManager.authenticate(creds);
//
//        // Generate token
////        String jwts = jwtService.getToken(auth.getName());
//        String jwts = tokenService.generateToken(auth);
//
//        // Build response with the generated token
//        return ResponseEntity.ok()
//                .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwts)
//                .header(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, "Authorization")
//                .build();
//
//    }
}
