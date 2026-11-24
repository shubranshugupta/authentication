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
- MySQL: Relational database for storing user information and tokens, with Flyway migrations.

## Getting Started

### Prerequisites

1. Java 21 or higher
2. Docker (runs MySQL, Redis and Mailpit for development, and the integration tests)
3. Maven is optional: the project includes the Maven wrapper (`./mvnw`, or `mvnw.cmd` on Windows)

### Installation

#### Clone the Repository

```bash
git clone https://github.com/shubranshugupta/authentication.git
cd authentication
```

#### Create the `env.properties` File

Copy the template to the project root. `env.properties` is git-ignored, so your secrets stay out of the repository.

```bash
cp env.properties.example env.properties
```

Then fill in `JWT_SECRET_KEY`: a base64 key of at least 32 bytes. Generate one with `openssl rand -base64 48`.

The database, Redis and mail defaults already match `docker-compose.yml`. Any setting can also be given as an environment variable, which takes priority over the file.

#### Start MySQL, Redis and Mailpit

```bash
docker compose --env-file env.properties up -d
```

MySQL is published on port `3307` (not 3306), so it doesn't clash with a MySQL server already installed locally. All services listen on `127.0.0.1` only.

[Mailpit](https://mailpit.axllent.org) is a fake mail server: in development, every email the app sends (verification links, OTPs) lands in its inbox at **http://localhost:8025** instead of a real mailbox. To send real emails from development instead, set `MAIL_HOST`, `MAIL_PORT`, `MAIL_USERNAME` and `MAIL_PASSWORD` (for Gmail, use an [App Password](https://support.google.com/accounts/answer/185833), not your account password).

#### Run the Application

```bash
./mvnw spring-boot:run
```

NOTE: The application will start at `http://localhost:8080`.

### Configuration Profiles

| Profile | How it's selected | Settings come from |
|---|---|---|
| `dev` | the default | environment variables, then `./env.properties`, then defaults matching `docker-compose.yml`. SQL logging is on. |
| `prod` | `SPRING_PROFILES_ACTIVE=prod` | environment variables only. There are no defaults for hosts or credentials: set `DB_HOST`, `DB_PORT`, `DB_DATABASE`, `DB_USER`, `DB_PASSWORD`, `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`, `JWT_SECRET_KEY`, `MAIL_HOST`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD` and `APP_BASE_URL`. |

### Database Migrations

The schema is managed by [Flyway](https://documentation.red-gate.com/flyway). Migrations live in `src/main/resources/db/migration` and run automatically at startup. Hibernate only validates the schema (`ddl-auto: validate`), so every schema change must be a new migration file (`V2__...sql`, `V3__...sql`, ...). Never edit a migration that has already run.

### Running the Tests

```bash
./mvnw verify
```

The integration tests start real MySQL and Redis containers with [Testcontainers](https://testcontainers.com), so Docker must be running. They don't need `env.properties`, and they never send real emails.

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
