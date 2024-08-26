# Authentication System

This project is a comprehensive authentication system built using Spring Boot. It incorporates multiple authentication mechanisms, including JWT tokens, OTP for two-factor authentication, password reset functionality, and email notifications. The system is designed following best practices, including SOLID principles, DRY, and design patterns for flexibility and scalability. It also includes role-based access control to manage user permissions.

## Features

- JWT Authentication: Secure authentication using JSON Web Tokens (JWT) for stateless sessions.
- Role-Based Access Control: Different roles for users to manage access to various parts of the application.
- Two-Factor Authentication (2FA): Adds an additional layer of security using OTP (One-Time Password).
- Password Reset: Allows users to reset their password via email.
- Email Notifications: Sends emails for new user registrations, password resets, and other significant events.
- Logging: Comprehensive logging to monitor the application and track issues.
- Caching: Uses Redis for caching and storing session-related data.

## Technologies Used

- Spring Boot: Main framework used for developing the application.
- Spring Security: Used for implementing security features like JWT, OAuth, and role-based access control.
- Redis: Used for caching and storing session-related data.
- Thymeleaf: Template engine for processing email templates.
- MySQL/PostgreSQL: Relational database for storing user information and tokens.

## Getting Started

### Prerequisites

1. Java 11 or higher
2. Maven
3. MySQL/PostgreSQL
4. Redis

### Installation

#### Clone the Repository

```bash
git clone https://github.com/yourusername/authentication-system.git
cd authentication-system
```

#### Create `env.properties` File

Create a new file named `env.properties` in the `src/main/resources` directory and add `DB_DATABASE`, `DB_USER`, `DB_PASSWORD`, `JWT_SECRET_KEY`, `MAIL_USERNAME`, and `MAIL_PASSWORD` properties.You can use the following template:

```properties
DB_USER=user
DB_PASSWORD=password
JWT_SECRET_KEY=key
MAIL_USERNAME=abc@gmail.com
MAIL_PASSWORD=gmailpassword
```

NOTE: Replace the values with your database, JWT secret key, and email credentials.
NOTE: If you are using Gmail, you need to enable "Less Secure Apps" in your Google account settings.
NOTE: You can also define these properties as environment variables. You can also write the properties directly in the `application.yml` file. But for this you need to remove `import` statement from `application.yml` file.

```yaml
spring:
  config:
    import: file:src\main\resources\env.properties
```

#### Configure Database

Create a new database in MySQL/PostgreSQL and update the  `application.yml` file with your database credentials.

#### Set Up Redis

Ensure that Redis is running on your machine and is accessible by the application. You can update the Redis configuration in the `application.yml` file if needed.

#### Run the Application

```bash
mvn spring-boot:run
```

NOTE: The application will start at `http://localhost:8080`.

## API Endpoints

1. User Registration: `POST /auth/register`
2. User Login: `POST /auth/login`
3. Refresh Token: `POST /auth/refresh`
4. Verify Email: `GET /auth/verify-email?token=token&email=email`
5. Password Reset Request: `POST /auth/reset-password?email=email`
6. Get User Profile: `GET /user/get-info`
7. Update User Profile: `PUT /user/update-info`
8. Delete User: `DELETE /user/delete`
9. Hello World: `GET /user/hello`

## Error Handling

The system is designed to handle and log errors efficiently. Custom exceptions are used to manage different types of errors, and meaningful messages are returned to the client.

## Contributing

Contributions are welcome! Please fork this repository and submit a pull request with your changes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
