# JWT Authentication User Management System

A complete Spring Boot REST application with JWT (JSON Web Token) authentication for secure user signup, login, and profile management.

## 🚀 Features

- **JWT Token-based Authentication** - Secure stateless authentication
- **User Registration & Login** - Complete user management
- **Role-based Authorization** - USER and ADMIN roles
- **Protected Endpoints** - Secure API access with JWT tokens
- **Password Encryption** - BCrypt password hashing
- **Input Validation** - Comprehensive request validation
- **H2 Database** - In-memory database for development

## 🛠 Technology Stack

- **Spring Boot 3.2.0** - Main framework
- **Spring Security** - Security framework
- **Spring Data JPA** - Database operations
- **JWT (JSON Web Tokens)** - Authentication tokens
- **H2 Database** - In-memory database
- **Lombok** - Reduces boilerplate code
- **MapStruct** - Object mapping
- **BCrypt** - Password encryption
- **Maven** - Build tool

## 📁 Project Structure

```
src/main/java/com/example/usermanagement/
├── controller/
│   └── UserController.java          # REST API endpoints
├── service/
│   └── UserService.java             # Business logic
├── repository/
│   ├── UserRepository.java          # User data access
│   └── RoleRepository.java          # Role data access
├── model/
│   ├── User.java                    # User entity
│   └── Role.java                    # Role entity
├── dto/
│   ├── UserSignupRequest.java       # Signup request DTO
│   ├── JwtAuthRequest.java          # Login request DTO
│   ├── JwtAuthResponse.java         # Login response DTO
│   └── UserResponse.java            # User response DTO
├── mapper/
│   └── UserMapper.java              # Object mapping
├── security/
│   ├── JwtTokenProvider.java        # JWT token operations
│   ├── JwtAuthenticationFilter.java # JWT authentication filter
│   ├── SecurityConfig.java          # Security configuration
│   └── CustomUserDetailsService.java # User details service
└── config/
    └── RoleInitializer.java         # Role initialization
```

## 🔐 JWT Implementation Deep Dive - Complete Code & Flow

### 1. JWT Token Provider (`JwtTokenProvider.java`)

**Purpose**: Handles all JWT token operations including generation, validation, and parsing.

#### Methods Overview:
| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `getSigningKey()` | None | `SecretKey` | Creates cryptographic key from JWT secret |
| `generateToken(String username)` | `username: String` | `String` | Generates JWT token with username and expiration |
| `getUsernameFromToken(String token)` | `token: String` | `String` | Extracts username from JWT token |
| `validateToken(String token)` | `token: String` | `boolean` | Validates JWT token authenticity and expiration |

#### Complete Class Code:
```java
@Component
public class JwtTokenProvider {
    
    @Value("${jwt.secret}")
    private String jwtSecret;
    
    @Value("${jwt.expiration}")
    private long jwtExpiration;
    
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }
    
    public String generateToken(String username) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpiration);
        
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                .compact();
    }
    
    public String getUsernameFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }
    
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}
```

#### Method-by-Method Explanation:

**`getSigningKey()`**
```java
private SecretKey getSigningKey() {
    return Keys.hmacShaKeyFor(jwtSecret.getBytes());
}
```
**Why used**: Creates a cryptographic key from the secret string for signing JWT tokens
**What it does**: Converts the JWT secret from application.properties into a SecretKey object
**Interview point**: This ensures the same secret is used consistently for signing and verifying tokens

**`generateToken(String username)`**
```java
public String generateToken(String username) {
    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + jwtExpiration);
    
    return Jwts.builder()
            .setSubject(username)
            .setIssuedAt(now)
            .setExpiration(expiryDate)
            .signWith(getSigningKey(), SignatureAlgorithm.HS512)
            .compact();
}
```
**Why used**: Creates a secure JWT token when user logs in successfully
**What it does**:
1. Gets current timestamp for token creation
2. Calculates expiration time (24 hours from now)
3. Builds JWT with username as subject
4. Signs with HMAC-SHA512 algorithm
5. Returns compact string format
**Interview point**: HMAC-SHA512 provides strong security, and expiration prevents indefinite access

**`getUsernameFromToken(String token)`**
```java
public String getUsernameFromToken(String token) {
    Claims claims = Jwts.parserBuilder()
            .setSigningKey(getSigningKey())
            .build()
            .parseClaimsJws(token)
            .getBody();
    return claims.getSubject();
}
```
**Why used**: Extracts username from JWT token for authentication
**What it does**:
1. Parses the JWT token using the same secret key
2. Extracts claims (payload) from the token
3. Returns the username from the subject claim
**Interview point**: This method is called by the filter to identify the user from the token

**`validateToken(String token)`**
```java
public boolean validateToken(String token) {
    try {
        Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token);
        return true;
    } catch (JwtException | IllegalArgumentException e) {
        return false;
    }
}
```
**Why used**: Verifies if a JWT token is valid and not expired
**What it does**:
1. Attempts to parse the token with the secret key
2. If parsing succeeds, token is valid
3. If parsing fails (expired, malformed, wrong signature), returns false
**Interview point**: This is the core security method that prevents unauthorized access

### 2. JWT Authentication Filter (`JwtAuthenticationFilter.java`)

**Purpose**: Intercepts all HTTP requests to validate JWT tokens and set up authentication context.

#### Methods Overview:
| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain)` | `request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain` | `void` | Main filter method that processes JWT tokens |
| `getJwtFromRequest(HttpServletRequest)` | `request: HttpServletRequest` | `String` | Extracts JWT token from Authorization header |

#### Complete Class Code:
```java
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = getJwtFromRequest(request);
            
            if (StringUtils.hasText(jwt) && jwtTokenProvider.validateToken(jwt)) {
                String username = jwtTokenProvider.getUsernameFromToken(jwt);
                
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception ex) {
            logger.error("Could not set user authentication in security context", ex);
        }
        
        filterChain.doFilter(request, response);
    }
    
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
```

#### Method-by-Method Explanation:

**`doFilterInternal()`**
```java
@Override
protected void doFilterInternal(HttpServletRequest request, 
                              HttpServletResponse response, 
                              FilterChain filterChain) throws ServletException, IOException {
    
    try {
        String jwt = getJwtFromRequest(request);
        
        if (StringUtils.hasText(jwt) && jwtTokenProvider.validateToken(jwt)) {
            String username = jwtTokenProvider.getUsernameFromToken(jwt);
            
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            UsernamePasswordAuthenticationToken authentication = 
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
    } catch (Exception ex) {
        logger.error("Could not set user authentication in security context", ex);
    }
    
    filterChain.doFilter(request, response);
}
```
**Why used**: This is the core filter that processes every HTTP request to check for JWT authentication
**What it does**:
1. **Extracts JWT** from Authorization header using `getJwtFromRequest()`
2. **Validates token** using `jwtTokenProvider.validateToken(jwt)`
3. **Extracts username** from valid token using `getUsernameFromToken()`
4. **Loads user details** from database using `userDetailsService.loadUserByUsername()`
5. **Creates authentication object** with user authorities and credentials
6. **Sets authentication context** in SecurityContextHolder for the current request
7. **Continues filter chain** to allow request processing
8. **Handles exceptions** gracefully without breaking the request flow
**Interview point**: This filter runs before every request and sets up the security context for Spring Security

**`getJwtFromRequest()`**
```java
private String getJwtFromRequest(HttpServletRequest request) {
    String bearerToken = request.getHeader("Authorization");
    if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
        return bearerToken.substring(7);
    }
    return null;
}
```
**Why used**: Extracts the actual JWT token from the Authorization header
**What it does**:
1. Gets the "Authorization" header from the HTTP request
2. Checks if the header exists and starts with "Bearer "
3. Removes the "Bearer " prefix (7 characters) to get the actual token
4. Returns null if header is missing or malformed
**Interview point**: This method handles the standard Bearer token format used in HTTP authentication

### 3. Security Configuration (`SecurityConfig.java`)

**Purpose**: Configures Spring Security with JWT authentication and defines access rules.

#### Methods Overview:
| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `filterChain(HttpSecurity, JwtAuthenticationFilter)` | `http: HttpSecurity, jwtAuthenticationFilter: JwtAuthenticationFilter` | `SecurityFilterChain` | Configures security rules and JWT filter |
| `passwordEncoder()` | None | `PasswordEncoder` | Creates BCrypt password encoder bean |

#### Complete Class Code:
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/login").permitAll()
                .requestMatchers("/api/users/signup").permitAll()
                .requestMatchers("/h2-console/**").permitAll()
                .anyRequest().authenticated()
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .headers(headers -> headers.frameOptions().disable())
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

#### Method-by-Method Explanation:

**`filterChain()`**
```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
    http
        .csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/auth/login").permitAll()
            .requestMatchers("/api/users/signup").permitAll()
            .requestMatchers("/h2-console/**").permitAll()
            .anyRequest().authenticated()
        )
        .sessionManagement(session -> session
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        )
        .headers(headers -> headers.frameOptions().disable())
        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
    
    return http.build();
}
```
**Why used**: This is the main security configuration that defines how Spring Security behaves
**What it does**:
1. **Disables CSRF** - Cross-Site Request Forgery protection is not needed for stateless JWT authentication
2. **Configures access rules**:
   - `/api/auth/login` - Public access (no authentication required for login)
   - `/api/users/signup` - Public access (no authentication required for registration)
   - `/h2-console/**` - Public access for database console during development
   - `anyRequest().authenticated()` - All other requests require authentication
3. **Sets stateless sessions** - No server-side session storage (JWT is stateless)
4. **Disables frame options** - Allows H2 console to work in iframe
5. **Adds JWT filter** - Processes JWT tokens before the default UsernamePasswordAuthenticationFilter
**Interview point**: This method configures the entire security behavior of the application

**`passwordEncoder()`**
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```
**Why used**: Provides password hashing for secure password storage
**What it does**: Creates a BCrypt password encoder bean that can be injected into services
**Interview point**: BCrypt is the industry standard for password hashing with built-in salt

### 4. Custom User Details Service (`CustomUserDetailsService.java`)

**Purpose**: Loads user details from database for Spring Security authentication.

#### Methods Overview:
| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `loadUserByUsername(String)` | `username: String` | `UserDetails` | Loads user details from database for Spring Security |

#### Complete Class Code:
```java
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    
    private final UserRepository userRepository;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole().getName())))
                .build();
    }
}
```

#### Method-by-Method Explanation:

**`loadUserByUsername()`**
```java
@Override
public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    
    return org.springframework.security.core.userdetails.User.builder()
            .username(user.getUsername())
            .password(user.getPassword())
            .authorities(Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole().getName())))
            .build();
}
```
**Why used**: This method is called by Spring Security to load user details for authentication
**What it does**:
1. **Finds user** in database by username using `userRepository.findByUsername()`
2. **Throws UsernameNotFoundException** if user not found (Spring Security handles this)
3. **Builds UserDetails object** using Spring Security's User.builder():
   - Sets username from database
   - Sets password (already hashed with BCrypt)
   - Creates authorities list with role prefix (e.g., "ROLE_USER", "ROLE_ADMIN")
4. **Returns UserDetails** object for Spring Security to use
**Interview point**: This method bridges your custom User entity with Spring Security's UserDetails interface

### 5. User Service (`UserService.java`)

**Purpose**: Contains business logic for user operations and JWT authentication.

#### Methods Overview:
| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `signup(UserSignupRequest)` | `request: UserSignupRequest` | `UserResponse` | Handles user registration with validation |
| `authenticateUser(JwtAuthRequest)` | `request: JwtAuthRequest` | `JwtAuthResponse` | Validates credentials and generates JWT token |
| `getUserProfile(String)` | `username: String` | `UserResponse` | Retrieves user profile data |
| `validateToken(String)` | `token: String` | `boolean` | Delegates token validation to JWT provider |
| `getUsernameFromToken(String)` | `token: String` | `String` | Delegates username extraction to JWT provider |

#### Complete Class Code:
```java
@Service
@RequiredArgsConstructor
public class UserService {
    
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    
    public UserResponse signup(UserSignupRequest request) {
        // Check if username already exists
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username already exists: " + request.getUsername());
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already exists: " + request.getEmail());
        }
        
        Role role = roleRepository.findByName(request.getRoleName())
                .orElseThrow(() -> new RuntimeException("Role not found: " + request.getRoleName()));
        
        User user = userMapper.toUser(request);
        user.setRole(role);
        
        // Encode password before saving
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        
        User savedUser = userRepository.save(user);
        return userMapper.toUserResponse(savedUser);
    }
    
    // JWT Authentication Methods
    public JwtAuthResponse authenticateUser(JwtAuthRequest request) {
        // Find user by username
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Invalid username or password"));
        
        // Check password using encoded comparison
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid username or password");
        }
        
        // Generate JWT token
        String token = jwtTokenProvider.generateToken(user.getUsername());
        
        // Return JWT response
        return JwtAuthResponse.builder()
                .token(token)
                .username(user.getUsername())
                .roleName(user.getRole().getName())
                .message("Login successful")
                .build();
    }
    
    public UserResponse getUserProfile(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return userMapper.toUserResponse(user);
    }
    
    public boolean validateToken(String token) {
        return jwtTokenProvider.validateToken(token);
    }
    
    public String getUsernameFromToken(String token) {
        return jwtTokenProvider.getUsernameFromToken(token);
    }
}
```

#### Method-by-Method Explanation:

**`signup(UserSignupRequest request)`**
```java
public UserResponse signup(UserSignupRequest request) {
    // Check if username already exists
    if (userRepository.existsByUsername(request.getUsername())) {
        throw new RuntimeException("Username already exists: " + request.getUsername());
    }
    if (userRepository.existsByEmail(request.getEmail())) {
        throw new RuntimeException("Email already exists: " + request.getEmail());
    }
    
    Role role = roleRepository.findByName(request.getRoleName())
            .orElseThrow(() -> new RuntimeException("Role not found: " + request.getRoleName()));
    
    User user = userMapper.toUser(request);
    user.setRole(role);
    
    // Encode password before saving
    user.setPassword(passwordEncoder.encode(user.getPassword()));
    
    User savedUser = userRepository.save(user);
    return userMapper.toUserResponse(savedUser);
}
```
**Why used**: Handles user registration with validation and password encryption
**What it does**:
1. **Validates uniqueness** - Checks if username and email already exist
2. **Finds role** - Gets the specified role from database
3. **Maps request to entity** - Converts DTO to User entity
4. **Encrypts password** - Uses BCrypt to hash the password
5. **Saves user** - Persists user to database
6. **Returns response** - Maps entity back to response DTO
**Interview point**: This method ensures data integrity and security during user registration

**`authenticateUser(JwtAuthRequest request)`**
```java
public JwtAuthResponse authenticateUser(JwtAuthRequest request) {
    // Find user by username
    User user = userRepository.findByUsername(request.getUsername())
            .orElseThrow(() -> new RuntimeException("Invalid username or password"));
    
    // Check password using encoded comparison
    if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
        throw new RuntimeException("Invalid username or password");
    }
    
    // Generate JWT token
    String token = jwtTokenProvider.generateToken(user.getUsername());
    
    // Return JWT response
    return JwtAuthResponse.builder()
            .token(token)
            .username(user.getUsername())
            .roleName(user.getRole().getName())
            .message("Login successful")
            .build();
}
```
**Why used**: This is the core authentication method that validates credentials and generates JWT tokens
**What it does**:
1. **Finds user** by username in database
2. **Validates password** using BCrypt's `matches()` method (compares plain text with hash)
3. **Generates JWT token** using `jwtTokenProvider.generateToken()`
4. **Builds response** with token, username, role, and success message
**Interview point**: This method demonstrates secure password comparison and JWT token generation

**`getUserProfile(String username)`**
```java
public UserResponse getUserProfile(String username) {
    User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new RuntimeException("User not found"));
    return userMapper.toUserResponse(user);
}
```
**Why used**: Retrieves user profile data for authenticated users
**What it does**:
1. **Finds user** by username in database
2. **Maps entity to DTO** using MapStruct mapper
3. **Returns user profile** without sensitive information like password
**Interview point**: This method shows how to safely return user data without exposing sensitive information

**`validateToken(String token)`**
```java
public boolean validateToken(String token) {
    return jwtTokenProvider.validateToken(token);
}
```
**Why used**: Delegates token validation to JwtTokenProvider
**What it does**: Simply calls the JWT provider's validation method
**Interview point**: This is a service layer wrapper for the JWT validation logic

**`getUsernameFromToken(String token)`**
```java
public String getUsernameFromToken(String token) {
    return jwtTokenProvider.getUsernameFromToken(token);
}
```
**Why used**: Delegates username extraction to JwtTokenProvider
**What it does**: Simply calls the JWT provider's username extraction method
**Interview point**: This is a service layer wrapper for the JWT parsing logic

### 6. User Controller (`UserController.java`)

**Purpose**: Provides REST API endpoints for user operations and JWT authentication.

#### Methods Overview:
| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `login(JwtAuthRequest)` | `request: JwtAuthRequest` | `ResponseEntity<JwtAuthResponse>` | Handles user login and returns JWT token |
| `logout()` | None | `ResponseEntity<Map<String, String>>` | Handles user logout (client-side token removal) |
| `signup(UserSignupRequest)` | `request: UserSignupRequest` | `ResponseEntity<UserResponse>` | Handles user registration |
| `getUserProfile()` | None | `ResponseEntity<UserResponse>` | Returns profile data for authenticated user |

#### Complete Class Code:
```java
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
```

#### Method-by-Method Explanation:

**`login(@Valid @RequestBody JwtAuthRequest request)`**
```java
@PostMapping("/auth/login")
public ResponseEntity<JwtAuthResponse> login(@Valid @RequestBody JwtAuthRequest request) {
    JwtAuthResponse response = userService.authenticateUser(request);
    return ResponseEntity.ok(response);
}
```
**Why used**: Handles user login requests and returns JWT token
**What it does**:
1. **Validates request** using `@Valid` annotation
2. **Calls service method** `userService.authenticateUser()`
3. **Returns JWT response** with token and user info
**Interview point**: This endpoint is public (no authentication required) and returns the JWT token

**`signup(@Valid @RequestBody UserSignupRequest request)`**
```java
@PostMapping("/users/signup")
public ResponseEntity<UserResponse> signup(@Valid @RequestBody UserSignupRequest request) {
    UserResponse response = userService.signup(request);
    return ResponseEntity.status(HttpStatus.CREATED).body(response);
}
```
**Why used**: Handles user registration requests
**What it does**:
1. **Validates request** using `@Valid` annotation
2. **Calls service method** `userService.signup()`
3. **Returns 201 status** with created user info
**Interview point**: This endpoint is public and returns HTTP 201 (Created) status

**`getUserProfile()`**
```java
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
```
**Why used**: Returns profile data for the currently authenticated user
**What it does**:
1. **Gets username** from Spring Security context (set by JWT filter)
2. **Calls service method** `userService.getUserProfile()`
3. **Returns user profile** data
**Interview point**: This endpoint is protected and requires valid JWT token

**`logout()`**
```java
@PostMapping("/auth/logout")
public ResponseEntity<Map<String, String>> logout() {
    Map<String, String> response = new HashMap<>();
    response.put("message", "Logged out successfully");
    return ResponseEntity.ok(response);
}
```
**Why used**: Handles user logout requests
**What it does**: Simply returns a success message (client-side token removal)
**Interview point**: JWT logout is client-side (token deletion), server doesn't track tokens

## 🔄 Complete JWT Flow Explanation

### **Step-by-Step Authentication Flow:**

1. **User Registration** (`POST /api/users/signup`):
   ```
   Client → UserController.signup() → UserService.signup() → Database
   ```

2. **User Login** (`POST /api/auth/login`):
   ```
   Client → UserController.login() → UserService.authenticateUser() → 
   JwtTokenProvider.generateToken() → Returns JWT token
   ```

3. **Protected Request** (`GET /api/users/profile`):
   ```
   Client (with JWT) → JwtAuthenticationFilter.doFilterInternal() → 
   JwtTokenProvider.validateToken() → CustomUserDetailsService.loadUserByUsername() → 
   SecurityContextHolder.setAuthentication() → UserController.getUserProfile()
   ```

### **Detailed Request Processing:**

**For Login Request:**
1. **Request comes to** `/api/auth/login`
2. **SecurityConfig** allows it (public endpoint)
3. **UserController.login()** receives request
4. **UserService.authenticateUser()** validates credentials
5. **JwtTokenProvider.generateToken()** creates JWT
6. **Response** contains JWT token

**For Protected Request:**
1. **Request comes to** `/api/users/profile` with JWT in Authorization header
2. **JwtAuthenticationFilter.doFilterInternal()** intercepts request
3. **getJwtFromRequest()** extracts token from "Bearer <token>"
4. **JwtTokenProvider.validateToken()** verifies token
5. **JwtTokenProvider.getUsernameFromToken()** extracts username
6. **CustomUserDetailsService.loadUserByUsername()** loads user details
7. **SecurityContextHolder.setAuthentication()** sets security context
8. **UserController.getUserProfile()** processes request
9. **Response** contains user profile data

## 🔧 Configuration

### JWT Properties (`application.properties`)
```properties
# JWT Configuration
jwt.secret=your-super-secret-key-here-make-it-very-long-and-secure-at-least-256-bits-long-for-production-use
jwt.expiration=86400000
jwt.header=Authorization
jwt.prefix=Bearer 
```

**Explanation:**
- **`jwt.secret`** - Secret key for signing JWT tokens (must be at least 256 bits)
- **`jwt.expiration`** - Token expiration time in milliseconds (24 hours)
- **`jwt.header`** - HTTP header name for JWT token
- **`jwt.prefix`** - Prefix for JWT token in Authorization header

### Dependencies (`pom.xml`)
```xml
<!-- JWT Dependencies -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.11.5</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>

<!-- Spring Security -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

## 🚀 How to Run

1. **Prerequisites:**
   - Java 17 or higher
   - Maven

2. **Run the application:**
   ```bash
   mvn spring-boot:run
   ```

3. **Access the application:**
   - Application: `http://localhost:8080`
   - H2 Console: `http://localhost:8080/h2-console`

## 📡 API Endpoints

### 1. User Registration
```http
POST /api/users/signup
Content-Type: application/json

{
    "username": "john_doe",
    "password": "password123",
    "email": "john@example.com",
    "fullName": "John Doe",
    "roleName": "USER"
}
```

**Response:**
```json
{
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "fullName": "John Doe",
    "roleName": "USER"
}
```

### 2. User Login (JWT Authentication)
```http
POST /api/auth/login
Content-Type: application/json

{
    "username": "john_doe",
    "password": "password123"
}
```

**Response:**
```json
{
    "token": "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJqb2huX2RvZSIsImlhdCI6MTYzNDU2Nzg5MCwiZXhwIjoxNjM0NjU0MjkwfQ...",
    "username": "john_doe",
    "roleName": "USER",
    "message": "Login successful"
}
```

### 3. Get User Profile (Protected Endpoint)
```http
GET /api/users/profile
Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJqb2huX2RvZSIsImlhdCI6MTYzNDU2Nzg5MCwiZXhwIjoxNjM0NjU0MjkwfQ...
```

**Response:**
```json
{
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "fullName": "John Doe",
    "roleName": "USER"
}
```

### 4. Logout
```http
POST /api/auth/logout
Authorization: Bearer <your_jwt_token>
```

**Response:**
```json
{
    "message": "Logged out successfully"
}
```

## 🔒 Security Flow

### Authentication Process:
1. **User sends login request** with username/password
2. **UserService validates credentials** against database
3. **JwtTokenProvider generates JWT token** with user info
4. **Client receives JWT token** in response
5. **Client includes JWT token** in subsequent requests
6. **JwtAuthenticationFilter validates token** on each request
7. **Spring Security sets authentication context** for valid tokens
8. **Protected endpoints allow access** to authenticated users

### Token Structure:
```
Header.Payload.Signature
```
- **Header**: Algorithm and token type
- **Payload**: User claims (username, expiration, etc.)
- **Signature**: HMAC-SHA512 signature for verification

## 🧪 Testing with cURL

### 1. User Registration
```bash
curl -X POST http://localhost:8080/api/users/signup \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123",
    "email": "test@example.com",
    "fullName": "Test User",
    "roleName": "USER"
  }'
```

### 2. User Login
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123"
  }'
```

### 3. Get Profile (with JWT token)
```bash
curl -X GET http://localhost:8080/api/users/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"
```

## 🗄 Database

- **H2 In-Memory Database** - No setup required
- **H2 Console**: `http://localhost:8080/h2-console`
- **JDBC URL**: `jdbc:h2:mem:testdb`
- **Username**: `sa`
- **Password**: `password`

## 🔧 Production Considerations

1. **Change JWT Secret**: Use a strong, unique secret key
2. **Database**: Replace H2 with production database (PostgreSQL, MySQL)
3. **Password Policy**: Implement strong password requirements
4. **Token Expiration**: Adjust based on security requirements
5. **HTTPS**: Always use HTTPS in production
6. **CORS**: Configure CORS for your frontend domain
7. **Logging**: Add proper logging and monitoring
8. **Rate Limiting**: Implement API rate limiting
9. **Error Handling**: Add comprehensive error handling
10. **Testing**: Add unit and integration tests

## 📚 Key Concepts Explained

### JWT (JSON Web Token)
- **Stateless**: No server-side session storage
- **Self-contained**: Contains all necessary user information
- **Signed**: Prevents tampering and ensures authenticity
- **Expirable**: Automatically expires after set time

### Spring Security
- **Filter Chain**: Processes requests through security filters
- **Authentication**: Verifies user identity
- **Authorization**: Controls access to resources
- **UserDetails**: Interface for user information

### BCrypt Password Hashing
- **One-way**: Cannot be reversed to plain text
- **Salt**: Adds random data to prevent rainbow table attacks
- **Adaptive**: Can be made slower as computers get faster
- **Secure**: Industry standard for password hashing

This implementation provides a complete, secure, and scalable JWT authentication system for your Spring Boot application. 