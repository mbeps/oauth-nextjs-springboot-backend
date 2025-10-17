# **Backend for Next.JS & Spring Boot OAuth System**

A robust OAuth 2.0 authentication backend built with Spring Boot 3 and MongoDB. 
This server handles secure GitHub OAuth integration, JWT token generation, and session management for the [Next.JS frontend](https://github.com/mbeps/oauth-nextjs-springboot-frontend). 

The application implements a dual-token authentication system with short-lived access tokens and long-lived refresh tokens, both stored as httpOnly cookies to prevent XSS attacks. 
MongoDB provides persistent storage for refresh tokens and invalidated access tokens, ensuring secure session management and proper token revocation. 
CORS is configured to allow cross-origin requests from the frontend whilst maintaining security.

# Features

## OAuth 2.0 Authentication
The application provides complete OAuth authentication functionality:
- GitHub OAuth 2.0 integration with Spring Security
- Automatic user authentication and authorisation
- Secure callback handling and token exchange
- Error handling for failed authentication attempts

## JWT Token Management
Token generation and validation:
- Dual-token system with access tokens (15 minutes by default) and refresh tokens (7 days by default)
- Automatic token generation upon successful OAuth login
- Token validation on protected endpoints
- Custom JWT claims with user information (ID, username, email, avatar)
- Token expiry handling and validation

## Token Refresh Mechanism
Token renewal without re-authentication:
- Automatic access token refresh using refresh tokens
- Refresh token rotation for enhanced security
- Token validation before refresh
- Persistent refresh token storage in MongoDB

## Protected API Endpoints
Secure endpoints requiring authentication:
- User profile information retrieval
- Protected data access endpoints
- Action endpoints for authenticated operations
- Request validation using JWT tokens

## Token Invalidation
Session termination:
- Access token invalidation on logout
- Refresh token revocation from database
- Automatic cleanup of expired tokens via MongoDB TTL
- Cookie deletion on logout

## Public Endpoints
Health check endpoints for monitoring:
- Public health check endpoint
- Authentication status verification
- No authentication required

# Requirements
These are the requirements needed to run the project:
- Java 17 or higher
- MongoDB 4.4 or higher
- GitHub OAuth Application credentials (Client ID and Client Secret)
- (Optional) [Next.JS frontend](https://github.com/mbeps/oauth-nextjs-springboot-frontend) running

# Stack
These are the main technologies used in this project:

## Back-End
- [**Java**](https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html): An object-oriented programming language with strong typing and extensive libraries.
- [**Spring Boot**](https://spring.io/projects/spring-boot): A framework for building production-ready applications with minimal configuration.
- [**Spring Security**](https://spring.io/projects/spring-security): Comprehensive security framework providing authentication and authorisation.
- [**Spring Security OAuth2 Client**](https://docs.spring.io/spring-security/reference/servlet/oauth2/client/index.html): OAuth 2.0 client implementation for Spring applications.
- [**Spring Data MongoDB**](https://spring.io/projects/spring-data-mongodb): Provides integration with MongoDB for data persistence.
- [**JJWT**](https://github.com/jwtk/jjwt): Java JWT library for creating and parsing JSON Web Tokens.
- [**Gradle**](https://gradle.org/): Build automation tool for dependency management and project building.

## Database
- [**MongoDB**](https://www.mongodb.com/): NoSQL database for storing refresh tokens and invalidated access tokens with TTL-based expiry.

## Front-End
- [**Next.JS Frontend**](https://github.com/mbeps/oauth-nextjs-springboot-frontend): A TypeScript and React-based frontend consuming the authentication APIs.

# Design

## Token Storage Strategy
The application uses httpOnly cookies for token storage rather than localStorage. 
This approach prevents XSS attacks as JavaScript cannot access httpOnly cookies. 
Access tokens have a 15-minute lifespan whilst refresh tokens last 7 days by default.
Both tokens are transmitted securely with the Secure flag in production.

## Database Architecture
MongoDB stores two collections:
- `refresh_tokens`: Stores valid refresh tokens with username, creation time, last used time, and expiry date
- `invalidated_access_tokens`: Stores invalidated access tokens until their natural expiry

Both collections use MongoDB's TTL indexes to automatically delete expired documents, eliminating the need for manual cleanup.

## JWT Token Structure
Access tokens contain user claims (ID, login, name, email, avatar URL) and a type field set to `access`. 
Refresh tokens contain minimal information with type set to "refresh". 
All tokens are signed using HMAC-SHA256 with a secret key.

## CORS Configuration
CORS is configured to accept requests from `http://localhost:3000` (frontend URL) with credentials enabled. Allowed methods include GET, POST, PUT, DELETE, and OPTIONS. This enables secure cross-origin communication whilst preventing unauthorised access.

## Authentication Flow
1. User initiates GitHub OAuth login
2. Spring Security handles OAuth callback
3. Backend generates access and refresh tokens
4. Tokens are set as httpOnly cookies
5. User is redirected to frontend dashboard
6. Subsequent requests include cookies automatically
7. JWT filter validates access tokens on protected endpoints

## Token Refresh Flow
1. Frontend detects expired access token (`401` response)
2. Frontend calls refresh endpoint with refresh token cookie
3. Backend validates refresh token from database
4. Backend generates new access token
5. New access token is set as httpOnly cookie
6. Original request is retried with new token

## Logout Flow
1. User initiates logout
2. Backend retrieves both tokens from cookies
3. Access token is added to invalidation list in MongoDB
4. Refresh token is deleted from database
5. Both cookies are deleted
6. User is redirected to login page

# Setting Up Project
These are simple steps to run the application locally. 

## 1. Clone the Project Locally
```sh
git clone https://github.com/mbeps/oauth-nextjs-springboot-backend.git
cd oauth-nextjs-springboot-backend
```

## 2. Set Up MongoDB
Ensure MongoDB is running locally on `mongodb://localhost:27017` or configure your MongoDB connection string. 
The application will automatically create the required collections and indexes.

## 3. Create GitHub OAuth Application
Create a GitHub OAuth application with the following settings:
- **Homepage URL**: `http://localhost:8080`
- **Authorization callback URL**: `http://localhost:8080/login/oauth2/code/github`

Note your Client ID and Client Secret for the next step.

**For Production**: Update the Homepage URL and Authorization callback URL to your production domain (e.g., `https://yourdomain.com` instead of `http://localhost:8080`).

## 4. Configure Application
Copy the `example.application.yaml` file in the project root and rename it to `application.yaml`:

```yaml
spring:
  application:
    name: oauth
  security:
    oauth2:
      client:
        registration:
          github:
            client-id: GITHUB_CLIENT_ID_HERE
            client-secret: GITHUB_CLIENT_SECRET_HERE
            scope:
              - user:email
              - read:user
  data:
    mongodb:
      uri: MONGODB_URI_HERE
      # Alternative configuration:
      # host: localhost
      # port: 27017
      # database: oauth_app

server:
  port: 8080

# JWT Configuration
jwt:
  secret: JTW_SECRET_HERE_256
  expiration: 86400000  # 24 hours in milliseconds
  access-token-expiration: 900000  # 15 minutes in milliseconds
  refresh-token-expiration: 604800000  # 7 days in milliseconds

# Frontend URL for redirects
frontend:
  url: http://localhost:3000

cookie:
  secure: false  # Set to true in production (requires HTTPS)
  same-site: Lax  # Options: Strict, Lax, None
```

`spring.security.oauth2.client.registration.github`:
- `client-id`: Your GitHub OAuth application Client ID obtained from GitHub Developer Settings
- `client-secret`: Your GitHub OAuth application Client Secret obtained from GitHub Developer Settings
- `scope`: OAuth scopes requesting access to user profile and email information

`spring.data.mongodb`:
- `uri`: MongoDB connection string specifying the database location and name (e.g., `mongodb://localhost:27017/oauth_db`)

`jwt`:
- `secret`: Secret key for signing JWT tokens (minimum 32 characters for HS256 algorithm)
- `access-token-expiration`: Lifespan of access tokens in milliseconds (default: 900000 = 15 minutes)
- `refresh-token-expiration`: Lifespan of refresh tokens in milliseconds (default: 604800000 = 7 days)

`frontend`:
- `url`: The URL of your frontend application for CORS configuration and redirects (e.g., `http://localhost:3000`)

`cookie`:
- `secure`: Whether cookies should only be sent over HTTPS (set to `false` for local development, `true` for production)
- `same-site`: Cookie SameSite attribute for CSRF protection (use `Lax` or `Strict`)

**For Production**: 
- Set `cookie.secure` to `true`
- Update `frontend.url` to your production frontend domain
- Use a strong, randomly generated `jwt.secret`
- Configure MongoDB with authentication and SSL/TLS

## 5. Build the Project
```sh
./gradlew build
```

## 6. Run the Application
```sh
./gradlew bootRun
```

The application should now be running on [`http://localhost:8080`](http://localhost:8080)

# Usage

## Authentication Flow
1. Frontend redirects user to `/oauth2/authorization/github`
2. User authenticates with GitHub
3. GitHub redirects to callback URL with authorization code
4. Backend exchanges code for access token
5. Backend retrieves user information from GitHub
6. Backend generates JWT tokens and sets cookies
7. User is redirected to frontend dashboard

## Accessing Protected Endpoints
Protected endpoints require valid JWT access token in cookies:

**Get User Information**
```http
GET /api/user
Cookie: jwt=<access_token>
```

**Get Protected Data**
```http
GET /api/protected/data
Cookie: jwt=<access_token>
```

**Perform Action**
```http
POST /api/protected/action
Cookie: jwt=<access_token>
Content-Type: application/json

{
  "action": "refresh_data"
}
```

## Token Refresh
When access token expires, call the refresh endpoint:
```http
POST /api/auth/refresh
Cookie: refresh_token=<refresh_token>
```

This returns a new access token as an httpOnly cookie.

## Checking Authentication Status
```http
GET /api/auth/status
Cookie: jwt=<access_token>
```

Returns authentication status and user information if authenticated.

## Logging Out
```http
POST /logout
Cookie: jwt=<access_token>; refresh_token=<refresh_token>
```

Invalidates tokens and deletes cookies.

## Public Endpoints
Public health check (no authentication required):
```http
GET /api/public/health
```

## Using Web UI
All the actions above can be executed through the Next.JS frontend given it is running.
The frontend app will be running on [http://localhost:3000](http://localhost:3000) and will require the backend server to be running correctly. 

More information can be found on the [Frontend for Next.JS & Spring Boot OAuth System](https://github.com/mbeps/oauth-nextjs-springboot-frontend) repository.

# References
- [Frontend for Next.JS & Spring Boot OAuth System Repository](https://github.com/mbeps/oauth-nextjs-springboot-frontend)
- [Spring Boot Documentation](https://docs.spring.io/spring-boot/documentation.html)
- [Spring Security OAuth2 Documentation](https://docs.spring.io/spring-security/reference/servlet/oauth2/index.html)
- [GitHub OAuth Documentation](https://docs.github.com/en/apps/oauth-apps)
- [JJWT Documentation](https://github.com/jwtk/jjwt)
- [Spring Data MongoDB Documentation](https://docs.spring.io/spring-data/mongodb/reference/)
- [MongoDB Documentation](https://www.mongodb.com/docs/)