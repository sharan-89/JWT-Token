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

## 🔐 JWT Implementation Deep Dive

### 1. JWT Token Provider (`JwtTokenProvider.java`)

**Purpose**: Handles all JWT token operations including generation, validation, and parsing.

#### Key Methods:

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
**What it does:**
- Creates a new JWT token with the username as subject
- Sets current time as issued date
- Sets expiration time (24 hours from now)
- Signs the token with HMAC-SHA512 algorithm
- Returns the compact JWT string

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
**What it does:**
- Parses the JWT token to extract claims
- Verifies the token signature
- Returns the username from the subject claim

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
**What it does:**
- Attempts to parse and verify the JWT token
- Returns true if token is valid and not expired
- Returns false if token is invalid, expired, or malformed

### 2. JWT Authentication Filter (`JwtAuthenticationFilter.java`)

**Purpose**: Intercepts all HTTP requests to validate JWT tokens and set up authentication context.

#### Key Method:

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
**What it does:**
1. **Extracts JWT** from Authorization header
2. **Validates token** using JwtTokenProvider
3. **Extracts username** from valid token
4. **Loads user details** from database
5. **Creates authentication object** with user authorities
6. **Sets authentication context** for the request
7. **Continues filter chain** to allow request processing

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
**What it does:**
- Extracts "Bearer " prefix from Authorization header
- Returns the actual JWT token string
- Returns null if header is missing or malformed

### 3. Security Configuration (`SecurityConfig.java`)

**Purpose**: Configures Spring Security with JWT authentication and defines access rules.

#### Key Method:

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
**What it does:**
1. **Disables CSRF** - Not needed for stateless JWT authentication
2. **Configures access rules:**
   - `/api/auth/login` - Public access (no authentication required)
   - `/api/users/signup` - Public access
   - `/h2-console/**` - Public access for database console
   - All other requests require authentication
3. **Sets stateless sessions** - No server-side session storage
4. **Disables frame options** - Allows H2 console to work
5. **Adds JWT filter** - Processes JWT tokens before other filters

### 4. Custom User Details Service (`CustomUserDetailsService.java`)

**Purpose**: Loads user details from database for Spring Security authentication.

#### Key Method:

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
**What it does:**
1. **Finds user** in database by username
2. **Throws exception** if user not found
3. **Builds UserDetails object** with:
   - Username and password
   - Authorities based on user role
4. **Returns UserDetails** for Spring Security

### 5. User Service (`UserService.java`)

**Purpose**: Contains business logic for user operations and JWT authentication.

#### Key Methods:

**`authenticateUser()`**
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
**What it does:**
1. **Validates credentials** against database
2. **Uses BCrypt** to compare passwords securely
3. **Generates JWT token** for authenticated user
4. **Returns response** with token and user info

**`getUserProfile()`**
```java
public UserResponse getUserProfile(String username) {
    User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new RuntimeException("User not found"));
    return userMapper.toUserResponse(user);
}
```
**What it does:**
- Retrieves user profile from database
- Maps user entity to response DTO
- Returns user profile data

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