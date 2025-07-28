package com.example.usermanagement.config;

import com.example.usermanagement.model.Role;
import com.example.usermanagement.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class RoleInitializer implements CommandLineRunner {
    
    private final RoleRepository roleRepository;
    
    @Override
    public void run(String... args) throws Exception {
        initializeRoles();
    }
    
    private void initializeRoles() {
        // Create USER role if it doesn't exist
        if (!roleRepository.existsByName("USER")) {
            Role userRole = Role.builder()
                    .name("USER")
                    .description("Regular user role")
                    .build();
            roleRepository.save(userRole);
            log.info("USER role created successfully");
        }
        
        // Create ADMIN role if it doesn't exist
        if (!roleRepository.existsByName("ADMIN")) {
            Role adminRole = Role.builder()
                    .name("ADMIN")
                    .description("Administrator role")
                    .build();
            roleRepository.save(adminRole);
            log.info("ADMIN role created successfully");
        }
        
        log.info("Role initialization completed");
    }
} 