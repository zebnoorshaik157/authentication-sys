# Multi-Provider Authentication System

A backend authentication and authorization system built with Java and Spring Boot, supporting email/password login, Google and GitHub OAuth2, JWT-based authentication, and role-based access control.

## Features

- User registration with BCrypt password hashing
- Email/password login
- JWT access and refresh tokens using HTTP cookies
- Refresh-token rotation and revocation
- Google and GitHub OAuth2 login
- OAuth account linking
- Password reset with email OTP verification
- USER and ADMIN role-based authorization
- Input validation and exception handling
- Admin APIs with pagination and sorting
- Swagger/OpenAPI documentation
- Automated tests

## Technology Stack

- Java 21
- Spring Boot
- Spring Security
- JWT and OAuth2
- MySQL 8.0
- Spring Data JPA and Hibernate
- Spring Mail
- Maven
- Postman
- Git and GitHub

## Architecture

The project follows a layered architecture:

- **Controller:** Handles HTTP requests and responses.
- **Service:** Contains business logic.
- **Repository:** Performs database operations.
- **Entity:** Represents database records.
- **Security:** Handles authentication, authorization, JWT validation, cookies, and OAuth2.

## Getting Started

### Prerequisites

- JDK 21
- MySQL 8.0
- Git

### Clone the Repository

```bash
git clone https://github.com/zebnoorshaik157/authentication-sys.git
cd authentication-sys
```

### Database Setup

Create a MySQL database named `authentication_system`.

Configure the database connection, JWT secret, email settings, and OAuth2 client credentials in your local application configuration. Use the property names required by the application.

**Never commit passwords, API credentials, OAuth secrets, or JWT signing secrets to GitHub.**

### Run the Application

On Windows:

```powershell
.\mvnw spring-boot:run
```

### Run Tests

```powershell
.\mvnw test
```

## API Documentation

After starting the application, open:

http://localhost:8080/swagger-ui/index.html

## Security

- Passwords are hashed using BCrypt.
- Access and refresh tokens have separate purposes and lifetimes.
- Refresh tokens support database-backed revocation and rotation.
- Protected endpoints enforce authentication and role-based access.
- Cookie-based authentication uses CSRF protections.
- Production deployments should use HTTPS and securely managed secrets.

## Author

**Zebnoor Shaik**

GitHub: [zebnoorshaik157](https://github.com/zebnoorshaik157)
