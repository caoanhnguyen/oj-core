package com.kma.ojcore.service;

import com.kma.ojcore.dto.response.UserResponse;
import com.kma.ojcore.entity.User;
import com.kma.ojcore.enums.EStatus;
import com.kma.ojcore.mapper.UserMapper;
import com.kma.ojcore.repository.UserRepository;
import com.kma.ojcore.dto.response.ApiResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * User Service for user management operations
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final UserMapper userMapper;

    @Transactional(readOnly = true)
    public ApiResponse<UserResponse> getUserById(UUID id) {
        User user = userRepository.findUserWithRolesById(id)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + id));

        UserResponse userResponse = userMapper.toUserResponse(user);
        return ApiResponse.<UserResponse>builder()
                .status(200)
                .message("User updated successfully")
                .data(userResponse)
                .build();
    }

    @Transactional(readOnly = true)
    public ApiResponse<UserResponse> getUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found with username: " + username));

        UserResponse userResponse = userMapper.toUserResponse(user);
        return ApiResponse.<UserResponse>builder()
                .status(200)
                .message("User updated successfully")
                .data(userResponse)
                .build();
    }

    @Transactional(readOnly = true)
    public ApiResponse<List<UserResponse>> getAllUsers() {
        List<User> users = userRepository.findAll();
        List<UserResponse> userResponses = users.stream()
                .map(userMapper::toUserResponse)
                .collect(Collectors.toList());

        return ApiResponse.<List<UserResponse>>builder()
                .status(200)
                .message("User updated successfully")
                .data(userResponses)
                .build();
    }

    @Transactional
    public ApiResponse<UserResponse> updateUser(Long id, User updatedUser) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + id));

        // Update only non-null fields
        if (updatedUser.getFullName() != null) {
            user.setFullName(updatedUser.getFullName());
        }
        if (updatedUser.getBio() != null) {
            user.setBio(updatedUser.getBio());
        }
        if (updatedUser.getAvatarUrl() != null) {
            user.setAvatarUrl(updatedUser.getAvatarUrl());
        }
        if (updatedUser.getPhoneNumber() != null) {
            user.setPhoneNumber(updatedUser.getPhoneNumber());
        }
        if (updatedUser.getAddress() != null) {
            user.setAddress(updatedUser.getAddress());
        }
        if (updatedUser.getCountry() != null) {
            user.setCountry(updatedUser.getCountry());
        }
        if (updatedUser.getCity() != null) {
            user.setCity(updatedUser.getCity());
        }
        if (updatedUser.getSchool() != null) {
            user.setSchool(updatedUser.getSchool());
        }
        if (updatedUser.getMajor() != null) {
            user.setMajor(updatedUser.getMajor());
        }
        if (updatedUser.getGithubUrl() != null) {
            user.setGithubUrl(updatedUser.getGithubUrl());
        }
        if (updatedUser.getWebsite() != null) {
            user.setWebsite(updatedUser.getWebsite());
        }

        User savedUser = userRepository.save(user);
        UserResponse userResponse = userMapper.toUserResponse(savedUser);

        return ApiResponse.<UserResponse>builder()
                .status(200)
                .message("User updated successfully")
                .data(userResponse)
                .build();
    }

    @Transactional
    public ApiResponse<Void> deleteUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + id));

        user.setStatus(EStatus.DELETED);
        userRepository.save(user);

        return ApiResponse.<Void>builder()
                .status(200)
                .message("User deleted successfully")
                .build();
    }
}

