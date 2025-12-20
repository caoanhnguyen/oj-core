package com.kma.ojcore.service.impl;

import com.kma.ojcore.dto.request.LoginRequest;
import com.kma.ojcore.dto.request.RegisterRequest;
import com.kma.ojcore.dto.response.JwtAuthenticationResponse;
import com.kma.ojcore.dto.response.UserResponse;
import com.kma.ojcore.entity.RefreshToken;
import com.kma.ojcore.entity.Role;
import com.kma.ojcore.entity.User;
import com.kma.ojcore.enums.Provider;
import com.kma.ojcore.exception.ResourceAlreadyExistsException;
import com.kma.ojcore.exception.ResourceNotFoundException;
import com.kma.ojcore.mapper.UserMapper;
import com.kma.ojcore.repository.RoleRepository;
import com.kma.ojcore.repository.UserRepository;
import com.kma.ojcore.security.UserPrincipal;
import com.kma.ojcore.security.jwt.JwtTokenProvider;
import com.kma.ojcore.service.AuthService;
import com.kma.ojcore.service.RefreshTokenService;
import com.kma.ojcore.utils.TokenCookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

/**
 * Authentication Service xử lý các chức năng liên quan đến xác thực và quản lý người dùng.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final UserMapper userMapper;
    private final RefreshTokenService refreshTokenService;
    private final TokenCookieUtil tokenCookieUtil;


    @Transactional
    @Override
    public JwtAuthenticationResponse login(LoginRequest loginRequest, HttpServletResponse httpResponse) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsernameOrEmail(),
                            loginRequest.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
            User user = userRepository.findById(userPrincipal.getId())
                    .orElseThrow(() -> new ResourceNotFoundException("User not found"));

            // Tạo access token
            String accessToken = tokenProvider.generateAccessToken(authentication);

            // Lưu refresh token vào database
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

            // Set access token vào cookie
            tokenCookieUtil.setTokenCookies(httpResponse, accessToken, refreshToken.getToken());

            return JwtAuthenticationResponse.builder()
                    .userId(userPrincipal.getId())
                    .username(userPrincipal.getUsername())
                    .email(userPrincipal.getEmail())
                    .fullName(user.getFullName())
                    .build();

        } catch (Exception e) {
            log.error("Login failed: {}", e.getMessage());
            throw new BadCredentialsException("Invalid username or password");
        }
    }

    @Transactional
    @Override
    public UserResponse register(RegisterRequest registerRequest) {
        // Check if username already exists
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            throw new ResourceAlreadyExistsException("Username is already taken");
        }

        // Check if email already exists
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            throw new ResourceAlreadyExistsException("Email is already in use");
        }

        // Create new user
        User user = User.builder()
                .username(registerRequest.getUsername())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .fullName(registerRequest.getFullName())
                .provider(Provider.LOCAL)
                .emailVerified(false)
                .build();

        // Assign default role
        Role userRole = roleRepository.getUserRole();

        Set<Role> roles = new HashSet<>();
        roles.add(userRole);

        user.setRoles(roles);
        User savedUser = userRepository.save(user);

        return userMapper.toUserResponse(savedUser);
    }

    @Transactional
    @Override
    public JwtAuthenticationResponse refreshToken(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        try {
            String refreshTokenStr = tokenCookieUtil.getCookieValue(httpRequest, tokenCookieUtil.REFRESH_TOKEN_COOKIE_NAME);

            // Tìm refresh token trong database
            RefreshToken refreshToken = refreshTokenService.findByToken(refreshTokenStr)
                    .orElseThrow(() -> new BadCredentialsException("Refresh token not found"));

            // Verify token chưa expired và chưa revoked
            refreshToken = refreshTokenService.verifyExpiration(refreshToken);

            User user = refreshToken.getUser();
            UserPrincipal userPrincipal = UserPrincipal.create(user);

            // Tạo access token mới
            String newAccessToken = tokenProvider.generateAccessToken(userPrincipal);

            // Tạo refresh token mới và revoke token cũ
            RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user);

            // Set access token vào cookie
            tokenCookieUtil.setTokenCookies(httpResponse, newAccessToken, newRefreshToken.getToken());

            return JwtAuthenticationResponse.builder()
                    .userId(user.getId())
                    .username(user.getUsername())
                    .email(user.getEmail())
                    .fullName(user.getFullName())
                    .build();
        } catch (Exception e) {
            log.error("Token refresh failed: {}", e.getMessage());
            throw new RuntimeException("Could not refresh token: " + e.getMessage());
        }
    }

    @Transactional
    @Override
    public void logout(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        try {
            String refreshTokenStr = tokenCookieUtil.getCookieValue(httpRequest, tokenCookieUtil.REFRESH_TOKEN_COOKIE_NAME);

            // Revoke refresh token trong database
            refreshTokenService.revokeToken(refreshTokenStr);

            // Xoá cookie access token và refresh token
            tokenCookieUtil.clearCookies(httpResponse);
        } catch (Exception e) {
            log.error("Logout failed: {}", e.getMessage());
            throw new RuntimeException("Error orcurred");
        }
    }

    @Override
    public UserResponse getCurrentUser(UserPrincipal currentUser) {
        User user = userRepository.findUserWithRolesById(currentUser.getId())
                .orElseThrow(() -> new RuntimeException("User not found"));

        return userMapper.toUserResponse(user);
    }
}

