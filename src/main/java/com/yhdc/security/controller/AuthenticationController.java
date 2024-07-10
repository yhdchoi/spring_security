package com.yhdc.security.controller;

import com.yhdc.security.dto.AuthenticationResponse;
import com.yhdc.security.dto.RegisterRequest;
import com.yhdc.security.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RequestMapping("/api/auth/jwt")
@RestController
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/regi")
    public ResponseEntity<AuthenticationResponse> registerUser(@RequestBody RegisterRequest registerRequest) {
        return ResponseEntity.ok(authenticationService.registerUser(registerRequest));
    }

}
