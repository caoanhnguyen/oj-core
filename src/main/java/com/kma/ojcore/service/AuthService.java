package com.kma.ojcore.service;

import com.kma.ojcore.dto.request.LoginRequest;
import com.kma.ojcore.dto.request.RegisterRequest;
import com.kma.ojcore.dto.response.JwtAuthenticationResponse;
import com.kma.ojcore.dto.response.UserResponse;
import com.kma.ojcore.security.UserPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface AuthService {

    JwtAuthenticationResponse login(LoginRequest loginRequest, HttpServletResponse httpResponse);

    UserResponse register(RegisterRequest registerRequest);

    JwtAuthenticationResponse refreshToken(HttpServletRequest httpRequest, HttpServletResponse httpResponse);

    void logout(HttpServletRequest httpRequest, HttpServletResponse httpResponse);

    UserResponse getCurrentUser(UserPrincipal currentUser);
}
