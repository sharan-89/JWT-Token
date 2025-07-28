package com.example.usermanagement.mapper;

import com.example.usermanagement.dto.UserSignupRequest;
import com.example.usermanagement.dto.UserResponse;
import com.example.usermanagement.model.User;
import org.springframework.stereotype.Component;

@Component
public class UserMapper {
    
    // Method 1: Convert User entity to UserResponse DTO
    public UserResponse toUserResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .roleName(user.getRole().getName())
                .build();
    }
    
    // Method 2: Convert UserSignupRequest DTO to User entity
    public User toUser(UserSignupRequest request) {
        return User.builder()
                .username(request.getUsername())
                .password(request.getPassword())
                .email(request.getEmail())
                .fullName(request.getFullName())
                .build();
    }
} 