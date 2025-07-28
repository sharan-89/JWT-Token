package com.example.usermanagement.controller;

import com.example.usermanagement.dto.JwtAuthRequest;
import com.example.usermanagement.dto.JwtAuthResponse;
import com.example.usermanagement.dto.UserResponse;
import com.example.usermanagement.dto.UserSignupRequest;
import com.example.usermanagement.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class UserController {
    
    private final UserService userService;
    
    // Auth Endpoints
    @PostMapping("/auth/login")
    public ResponseEntity<JwtAuthResponse> login(@Valid @RequestBody JwtAuthRequest request) {
        JwtAuthResponse response = userService.authenticateUser(request);
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/auth/logout")
    public ResponseEntity<Map<String, String>> logout() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "Logged out successfully");
        return ResponseEntity.ok(response);
    }
    
    // User Endpoints
    @PostMapping("/users/signup")
    public ResponseEntity<UserResponse> signup(@Valid @RequestBody UserSignupRequest request) {
        UserResponse response = userService.signup(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
    
    // Protected Endpoints (need JWT token)
    @GetMapping("/users/profile")
    public ResponseEntity<UserResponse> getUserProfile() {
        // Get current authenticated user from Spring Security context
        String username = org.springframework.security.core.context.SecurityContextHolder
                .getContext()
                .getAuthentication()
                .getName();
        
        UserResponse response = userService.getUserProfile(username);
        return ResponseEntity.ok(response);
    }
} 