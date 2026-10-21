# Multi-Provider Authentication & Authorization System

A backend-focused authentication and authorization system built with **Java, Spring Boot, Spring Security, JWT, OAuth2, and MySQL**.

The application supports email/password authentication and social login through **Google and GitHub**. It demonstrates secure password hashing, cookie-based access and refresh tokens, refresh-token rotation and revocation, role-based authorization, OTP-based password recovery, OAuth account linking, request validation, centralized exception handling, and interactive API documentation with Swagger UI.

> **Project status:** The core backend has been implemented and tested locally. The project test run recorded **68 tests, 0 failures, 0 errors, and 0 skipped tests**. Deployment links should be added here only after a live deployment has been completed and verified.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [Architecture](#architecture)
- [Authentication and Authorization Flows](#authentication-and-authorization-flows)
- [Security Design](#security-design)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Running the Application](#running-the-application)
- [API Documentation](#api-documentation)
- [API Feature Reference](#api-feature-reference)
- [Testing](#testing)
- [Postman](#postman)
- [Database Design](#database-design)
- [Design Decisions](#design-decisions)
- [Future Improvements](#future-improvements)
- [What This Project Demonstrates](#what-this-project-demonstrates)
- [Author](#author)

---

## Overview

Authentication and authorization are essential parts of modern applications. This project explores how to build an authentication backend that supports both local credentials and external identity providers while keeping request handling, business logic, security, and persistence responsibilities separated.

For local authentication, passwords are hashed before storage. After successful authentication, the application issues JWT access and refresh tokens through HTTP cookies. Refresh-token records are tracked so refresh sessions can be rotated and revoked. Google and GitHub OAuth2 login are handled through Spring Security's OAuth2 flow, with provider-aware account handling and support for linking an external provider account.

The application also includes OTP-based password recovery, role-based access control, user-management functionality, validation, centralized error handling, and Swagger/OpenAPI documentation.

## Key Features

### Authentication

- User registration
- Email-and-password login
- Password hashing with BCrypt
- JWT-based authentication for protected requests
- Separate access and refresh tokens
- Access and refresh tokens delivered through cookies
- Refresh-token rotation
- Refresh-token revocation during logout
- Cookie settings that can be configured for the environment

### OAuth2 Login and Account Linking

- Google OAuth2 sign-in
- GitHub OAuth2 sign-in
- Provider-aware OAuth2 user handling
- Custom OAuth2 login success handling
- OAuth account records
- Linking a provider account to an existing application account
- Provider-specific authentication processing

### Password Recovery

- Email-based password recovery
- One-time password (OTP) generation and email delivery
- OTP verification
- OTP expiration validation
- Password reset after successful verification
- BCrypt hashing for the new password

### Authorization and Security

- Spring Security integration
- Role-based authorization with `USER` and `ADMIN` roles
- JWT authentication filter
- Stateless API authentication
- Separate access-token and refresh-token handling
- Refresh-token rotation and revocation
- HttpOnly cookie support
- Configurable cookie security attributes
- Account-enabled checks where configured
- Centralized handling of authentication and API errors

### User and OAuth Account Management

- User registration and retrieval
- User updates and deletion where exposed by the API
- User lookup by email where exposed by the API
- Pagination and sorting for supported listing endpoints
- OAuth account linking
- DTO-based request and response handling

### API and Backend Quality

- REST-style endpoints
- Layered architecture
- Spring Data JPA and Hibernate persistence
- Jakarta Bean Validation
- Centralized exception handling
- Swagger/OpenAPI documentation
- Postman-based API testing
- Automated test suite

---

## Technology Stack

| Technology | Purpose |
|---|---|
| Java 21 | Programming language |
| Spring Boot 4 | Application framework |
| Spring Security | Authentication and authorization |
| Spring Data JPA | Repository and persistence abstraction |
| Hibernate | Object-relational mapping |
| MySQL | Relational database |
| JJWT | JWT creation and validation |
| OAuth2 Client | Google and GitHub sign-in |
| Spring Mail | Email delivery for OTP-based password recovery |
| Jakarta Bean Validation | Request validation |
| Maven Wrapper | Build and dependency management |
| SpringDoc OpenAPI / Swagger UI | API documentation and interactive endpoint testing |
| Postman | Manual API testing and request organization |

The exact dependency versions are defined in `pom.xml`.

---

## Architecture

The application uses a layered backend architecture. HTTP requests enter through controllers, business rules are handled in services, repositories manage persistence, and MySQL stores application data.

```text
                         CLIENT
                           |
                           v
                    HTTP API Request
                           |
                           v
                Spring Security Filter Chain
                           |
                +----------+-----------+
                |                      |
                v                      v
       JWT Authentication       OAuth2 Login Flow
             Filter                    |
                |                      v
                |              OAuth2 User Service
                |                      |
                |                      v
                |              Success / Failure
                |                  Handlers
                |                      |
                +----------+-----------+
                           |
                           v
                     REST Controllers
                           |
                           v
                      Service Layer
                           |
                           v
                    Repository Layer
                           |
                           v
                      MySQL Database
```

Supporting components include the JWT service, cookie handling, password encoder, email service, request/response DTOs, validation, and centralized exception handling.

### Main Components

| Component | Responsibility |
|---|---|
| Controllers | Receive HTTP requests and return API responses |
| DTOs | Define request and response data without exposing persistence entities directly |
| Services | Apply authentication, account-management, token, and password-recovery rules |
| Repositories | Read and write application data through Spring Data JPA |
| JWT service | Create and validate JWTs and read their claims |
| JWT filter | Inspect incoming requests and establish authentication for valid access tokens |
| Spring Security configuration | Define security behavior and integrate authentication mechanisms |
| OAuth2 user service | Process identity information returned by supported providers |
| OAuth2 success handler | Complete application behavior after successful OAuth2 authentication |
| Cookie handling | Set and clear authentication cookies |
| Email service | Deliver password-recovery OTP messages |
| Exception handling | Convert application errors into consistent API responses |

---

## Authentication and Authorization Flows

### 1. Registration

```text
Client
  |
  | Registration request
  v
Authentication Controller
  |
  v
Authentication Service
  |
  +--> Validate request
  |
  +--> Hash password with BCrypt
  |
  v
User Repository
  |
  v
MySQL
```

The application validates registration input, hashes the password, and persists the user record. A raw password should never be stored in the database.

### 2. Email-and-Password Login

```text
Client
  |
  | Email + Password
  v
Login Endpoint
  |
  v
Spring Security Authentication
  |
  v
Credential Verification
  |
  v
JWT Service
  |
  +--> Access Token
  |
  +--> Refresh Token with token identifier (jti)
  |
  v
HTTP Cookies
```

After successful credential verification, the application creates the token pair and delivers the tokens through cookies. The refresh-token record is tracked server-side to support lifecycle management.

### 3. Access-Token Authentication

```text
Incoming API Request
  |
  v
JWT Authentication Filter
  |
  v
Read Access Token
  |
  v
Validate Token
  |
  v
Load / Establish User Authentication
  |
  v
Spring Security Context
  |
  v
Protected Controller
```

A protected request must satisfy the application's security rules. A missing, invalid, or expired access token should not be treated as authenticated.

### 4. Refresh-Token Rotation

```text
Client sends refresh request
  |
  v
Validate Refresh Token
  |
  v
Check Token / Session Record
  |
  v
Create Replacement Token Pair
  |
  v
Rotate or Revoke Previous Refresh Token
  |
  v
Set Updated Cookies
```

Refresh-token rotation replaces the refresh token used for renewal. Server-side tracking supports revocation and reduces the risk of continued use of a token that has been invalidated.

### 5. Logout

```text
Logout Request
  |
  v
Read and Validate Refresh Token
  |
  v
Identify Refresh-Token Record
  |
  v
Revoke Refresh Token
  |
  v
Clear Authentication Cookies
  |
  v
Return API Response
```

Logout is intended to invalidate the tracked refresh session and clear the client's authentication cookies rather than relying only on client-side token deletion.

### 6. OTP-Based Password Recovery

```text
User submits recovery request
  |
  v
Verify Email / Start Recovery
  |
  v
Generate OTP
  |
  v
Send OTP by Email
  |
  v
User submits OTP
  |
  v
Validate OTP and Expiration
  |
  v
Issue / Validate Recovery Authorization
  |
  v
User submits New Password
  |
  v
Hash New Password with BCrypt
  |
  v
Update User Record
```

The implemented recovery flow uses email verification, OTP verification, and password reset as separate steps. Follow the exact request fields and order documented by Swagger for the current build.

### 7. Google and GitHub OAuth2 Login

```text
User
  |
  v
Google or GitHub
  |
  v
OAuth2 Authorization Callback
  |
  v
Custom OAuth2 User Handling
  |
  v
Find or Create Application Account
  |
  v
OAuth2 Success Handler
  |
  v
Application Authentication Result
```

OAuth2 delegates the external identity step to the provider. The application then processes provider information and associates it with its own user/account model.

### 8. OAuth Account Linking

```text
Authenticated Application User
  |
  v
Start Provider Linking
  |
  v
Complete Google / GitHub OAuth2 Flow
  |
  v
Validate Provider Identity
  |
  v
Associate Provider Account
  |
  v
Persist OAuth Account Link
```

Account linking allows a user to associate a supported external provider identity with an existing application account. The API's security requirements and response details are documented in Swagger.

### 9. Role-Based Authorization

The application defines `USER` and `ADMIN` roles. Authentication establishes who the caller is; authorization determines which operations that caller may access. The actual role requirements are enforced by the application's Spring Security configuration and endpoint/service rules.

---

## Security Design

### Password Storage

- Passwords are hashed with BCrypt before storage.
- Password recovery applies BCrypt to the replacement password.
- Raw passwords should not be logged or persisted.

### JWT Handling

- Access and refresh tokens serve different purposes.
- JWT signatures and claims are validated before tokens are trusted.
- Refresh tokens are tracked server-side for rotation and revocation.
- The refresh-token identifier (`jti`) supports identifying a token record.
- JWT signing secrets must be supplied through configuration and never committed to source control.

### Cookie Handling

Authentication tokens are delivered using cookies. Cookie attributes should be configured for the deployment environment.

Relevant settings include:

- `HttpOnly`, to prevent ordinary client-side JavaScript from reading the cookie
- `Secure`, to restrict cookie transmission to HTTPS when enabled
- `SameSite`, to control cross-site cookie behavior
- Cookie names and optional domain configuration

Cookie-based authentication must be paired with an appropriate CSRF strategy for the deployment. Do not assume that `HttpOnly` alone prevents CSRF.

### OAuth2

- Google and GitHub are supported external identity providers.
- Provider-specific identity data is handled through OAuth2 components.
- OAuth account linking is represented separately from the user record.
- Client IDs and client secrets must be configured outside committed source files.

### Configuration and Error Handling

- Environment variables are used for sensitive configuration.
- Request validation helps reject malformed input.
- Centralized exception handling provides consistent error responses.
- Authentication endpoints should avoid exposing secrets or unnecessary account details in error messages.

---

## Project Structure

The project uses the Java package `com.authsystem`. The structure below describes the main architectural areas; exact filenames may evolve as the project develops.

```text
authentication-system/
├── src/
│   ├── main/
│   │   ├── java/com/authsystem/
│   │   │   ├── controller/
│   │   │   ├── dto/
│   │   │   ├── entity/
│   │   │   ├── exception/
│   │   │   ├── repository/
│   │   │   ├── security/
│   │   │   │   ├── filter/
│   │   │   │   └── jwt/
│   │   │   ├── service/
│   │   │   └── configuration/
│   │   └── resources/
│   │       └── application.properties
│   └── test/
│       └── java/
├── .gitignore
├── mvnw
├── mvnw.cmd
├── pom.xml
└── README.md
```

Key areas:

- `controller/` — HTTP endpoints
- `dto/` — request and response models
- `entity/` — JPA entities
- `repository/` — database access
- `service/` — application business logic
- `security/filter/` — request authentication filtering
- `security/jwt/` — JWT-related functionality
- `configuration/` — application and security configuration
- `src/test/` — automated tests

---

## Getting Started

### Prerequisites

Install or configure:

- Java Development Kit (JDK) 21
- MySQL 8
- Git
- An IDE such as Visual Studio Code or IntelliJ IDEA

The repository includes the Maven Wrapper, so you can build the project without a globally installed Maven command.

### 1. Clone the Repository

```bash
git clone https://github.com/zebnoorshaik157/authentication-sys.git
cd authentication-sys
```

### 2. Create the Database

Create a MySQL database for the application. The current local database name used during development is:

```sql
CREATE DATABASE authentication_system;
```

Configure the connection settings for your local MySQL instance. Do not commit database passwords.

### 3. Configure Environment Variables

Set the database, JWT, mail, and OAuth2 configuration required by your local `application.properties`. The names and required values must match the placeholders used in your current configuration file.

See [Configuration](#configuration) below. Never share or commit actual secrets.

### 4. Run the Application

**Windows PowerShell:**

```powershell
.\mvnw spring-boot:run
```

**Linux/macOS:**

```bash
./mvnw spring-boot:run
```

The application uses port `8080` by default unless the application configuration overrides it.

### 5. Verify the Application

When the application starts successfully, open:

- Swagger UI: `http://localhost:8080/swagger-ui/index.html`
- OpenAPI JSON: `http://localhost:8080/v3/api-docs`

If these URLs cannot be reached, first confirm that the Spring Boot application has started successfully and is listening on the configured port.

---

## Configuration

Sensitive values should be supplied through environment variables or a local configuration file that is excluded from Git. The exact variable names depend on the placeholders in the current `application.properties`.

The application needs configuration for these categories:

| Configuration category | Purpose |
|---|---|
| MySQL URL, username, password | Database connection |
| JWT signing secret | Signing and validating JWTs |
| JWT issuer and token lifetimes | Token claims and expiration |
| Access/refresh cookie names | Cookie identification |
| Cookie `Secure`, `HttpOnly`, `SameSite`, and domain settings | Cookie behavior |
| SMTP username and password | Sending recovery emails |
| OTP validity duration | OTP expiration policy |
| Google OAuth2 client ID and secret | Google login |
| GitHub OAuth2 client ID and secret | GitHub login |

### Important Secret-Handling Rules

Never commit values such as:

```text
Database passwords
JWT signing secrets
SMTP credentials
Google OAuth2 client secrets
GitHub OAuth2 client secrets
```

The repository should contain safe examples or documentation for configuration—not live credentials. The local `application.properties` used during development is ignored by Git, so keep it local and secure.

For production, use the hosting provider's secret/environment-variable settings rather than committing secrets into the repository.

---

## Running the Application

### Build and Test

Run the test suite with the Maven Wrapper.

**Windows PowerShell:**

```powershell
.\mvnw test
```

To package the application:

```powershell
.\mvnw package
```

If a test or build fails, inspect the first meaningful error in the terminal output before changing code.

### Run Locally

```powershell
.\mvnw spring-boot:run
```

Stop the running application with `Ctrl+C` in the terminal where it is running.

---

## API Documentation

The project includes Swagger UI through SpringDoc OpenAPI.

When the backend is running locally:

- **Swagger UI:** `http://localhost:8080/swagger-ui/index.html`
- **OpenAPI specification (JSON):** `http://localhost:8080/v3/api-docs`

Swagger UI provides a live view of the endpoints exposed by the running application, their request schemas, response schemas, parameters, and available operations. Where supported by the endpoint's security configuration, it can also send test requests.

The OpenAPI JSON endpoint exposes the generated API specification. Swagger does not automatically act as a permanent database for test history; use Postman or another tool when you need to organize and save reusable requests.

**Use the running Swagger specification as the source of truth for exact paths, request fields, and response codes.** This avoids documenting routes that may not match the current controller mappings.

---

## API Feature Reference

The backend's API functionality is grouped into the following areas. For exact HTTP methods, endpoint paths, required fields, status codes, and response examples, open Swagger UI for the current build.

| API area | Purpose |
|---|---|
| Registration | Create a local user account |
| Login | Authenticate using email and password |
| Token refresh | Validate a refresh session and issue replacement tokens |
| Logout | Revoke the refresh session and clear authentication cookies |
| Password recovery | Start recovery, verify an OTP, and reset the password |
| OAuth2 login | Authenticate using Google or GitHub |
| OAuth account linking | Associate a provider identity with an application account |
| User management | Perform the user operations exposed by the application |
| Pagination and sorting | Retrieve supported collections in pages and chosen sort order |
| Protected operations | Apply authentication and role-based access rules |

### Recommended Manual Test Sequence

1. Register a test user.
2. Log in and confirm the authentication response/cookies.
3. Call a protected endpoint with the authenticated session.
4. Refresh the token pair.
5. Verify that the previous refresh token is no longer accepted when rotation/revocation applies.
6. Log out and verify that the session is revoked and cookies are cleared.
7. Exercise the email OTP recovery flow using a configured test email account.
8. Test Google and GitHub OAuth2 only after configuring valid provider credentials and callback URLs.
9. Test OAuth account linking with an authenticated application user.
10. Verify access restrictions for `USER` and `ADMIN` roles.

Use test accounts and never publish real tokens, cookies, passwords, or OAuth credentials in screenshots or issue reports.

---

## Testing

The automated test suite was run successfully during development.

| Result | Count |
|---|---:|
| Tests run | 68 |
| Failures | 0 |
| Errors | 0 |
| Skipped | 0 |
| Build result | `BUILD SUCCESS` |

To rerun the suite on your machine:

```powershell
.\mvnw test
```

Test results can change when code or configuration changes, so rerun the command before reporting a new result.

Manual API testing is also performed using Postman and Swagger UI. The automated test suite and manual API checks serve different purposes: automated tests can be repeated consistently, while manual checks help verify request flows and inspect actual responses.

---

## Postman

Postman is useful for keeping reusable API requests organized and testing multi-step flows. The project has been tested through Postman during development.

Recommended request folders:

- Authentication — register and login
- Token lifecycle — refresh and logout
- Password recovery — email verification, OTP verification, and password reset
- OAuth2 and account linking
- User management
- Authorization and negative tests

For cookie-based authentication, confirm that Postman is retaining and sending the expected cookies. Save reusable requests and example bodies, but remove real credentials and live token values before sharing a collection.

If a Postman collection is included in the repository, update the README with its exact committed filename after verifying it in the project root.

---

## Database Design

The backend uses MySQL with Spring Data JPA and Hibernate.

The main data concepts include:

| Data concept | Purpose |
|---|---|
| User | Application user details, credentials, and role-related information |
| Refresh-token record | Server-side refresh-token lifecycle tracking, including rotation/revocation data |
| OAuth account | Links an application user to an external provider identity |
| Password-recovery data | Supports the OTP-based recovery process |

The exact table and column names are defined by the project's entity mappings and database configuration. Inspect those mappings or the database schema for the authoritative names.

During development, Hibernate/JPA manages persistence according to the configured schema strategy. For production deployments, consider using Flyway or Liquibase migrations so schema changes are explicit, reviewable, and repeatable.

---

## Design Decisions

### 1. Layered Architecture

Controllers, services, and repositories have separate responsibilities. This reduces the amount of business logic inside HTTP controllers and makes the code easier to test and maintain.

```text
Controller
    |
    v
Service
    |
    v
Repository
    |
    v
Database
```

### 2. DTOs for API Boundaries

Request and response DTOs provide a boundary between the API contract and database entities. This reduces direct exposure of persistence models and lets request validation be handled at the API layer.

### 3. BCrypt for Passwords

Passwords are stored as BCrypt hashes rather than plaintext. Password verification uses the password-encoding mechanism instead of comparing stored plaintext passwords.

### 4. Separate Access and Refresh Tokens

Access tokens and refresh tokens have different responsibilities and lifetimes. Tracking refresh tokens server-side supports rotation and revocation, while access tokens are used to authenticate protected requests.

### 5. Cookie-Based Token Delivery

Delivering tokens through cookies can reduce exposure to JavaScript when `HttpOnly` is enabled. Cookie configuration still needs to be combined with HTTPS and an appropriate CSRF/CORS strategy for the deployment.

### 6. OAuth2 Provider Handling

Google and GitHub authentication are integrated through Spring Security OAuth2 components. Provider-aware account handling and a separate OAuth account model support external identities without treating provider login as the same operation as local password authentication.

### 7. Centralized Validation and Error Handling

Validation and global exception handling keep input checks and error responses consistent across the API, making behavior easier to understand and test.

### 8. Persistent Refresh-Token Lifecycle

Refresh-token persistence supports tracking token identifiers, rotating refresh sessions, and revoking sessions during logout. This provides more control than relying only on a token stored on the client.

---

## Future Improvements

Potential enhancements for a more production-ready deployment include:

- Deploy the backend and connect it to a managed MySQL database
- Add verified live deployment and Swagger links to this README
- Add Docker and production deployment configuration
- Add a CI/CD pipeline that runs tests on each change
- Introduce Flyway or Liquibase database migrations
- Add rate limiting for login and OTP endpoints
- Add OTP attempt limits and abuse protections
- Review account lockout and brute-force protection
- Document and verify the CSRF strategy for cookie-based authentication
- Add more integration tests for OAuth2, cookies, and token rotation
- Add security-focused tests for revoked and expired tokens
- Improve production monitoring, structured logging, and health checks
- Review refresh-token cleanup and retention policies
- Expand role and permission management if the application requirements grow

These are possible next steps, not claims that every item is already implemented.

---

## What This Project Demonstrates

This project brings together practical backend engineering concepts:

```text
Java
 |
 v
Spring Boot
 |
 v
Layered REST API
 |
 v
Spring Security
 |
 +--> Local Authentication
 |
 +--> Google / GitHub OAuth2
 |
 v
JWT Access and Refresh Tokens
 |
 v
Refresh-Token Rotation and Revocation
 |
 v
Role-Based Authorization
 |
 v
OTP Password Recovery
 |
 v
Email Integration
 |
 v
MySQL / JPA / Hibernate
 |
 v
Validation and Exception Handling
 |
 v
Swagger / OpenAPI
 |
 v
Automated and Manual API Testing
```

It is intended to demonstrate more than basic CRUD operations: the project combines identity handling, token lifecycle management, external authentication providers, persistence, and API security in a structured Spring Boot backend.

---

## Author

**Zebnoor Shaik**

- GitHub: [zebnoorshaik157](https://github.com/zebnoorshaik157)
- Project repository: [authentication-sys](https://github.com/zebnoorshaik157/authentication-sys)

---

## License

Add a license file and update this section if you decide to distribute the project under a specific open-source license.
