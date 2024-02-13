package com.medev.springsecurity6.service;

import com.medev.springsecurity6.dto.AuthenticationRequest;
import com.medev.springsecurity6.dto.AuthenticationResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public interface AuthService {

    AuthenticationResponse register(AuthenticationRequest request);
    AuthenticationResponse login(AuthenticationRequest request);

    void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException;
}
