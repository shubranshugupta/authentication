# Authentication System

This project is a comprehensive authentication system built using Spring Boot. It covers registration with email verification, login with JWT access tokens, password reset and account deletion with emailed codes, and email notifications. The system is designed following best practices, including SOLID principles, DRY, and design patterns for flexibility and scalability. It also includes role-based access control to manage user permissions.

## Features

- JWT Authentication: Short-lived access tokens (JWT, 15 minutes) that stop working at once after a logout or a password reset.
- Sessions: One session per device, with refresh tokens that work once and are stored only as hashes. Users can list their sessions and log out of them.
- Rate Limiting: Limits on wrong passwords, code guesses, registrations and emails.
- Role-Based Access Control: Different roles for users to manage access to various parts of the application.
- Emailed Codes and Links: Verify an email, reset a password or delete an account. They are stored only as hashes, work once, expire, and stop working after 5 wrong guesses.
- Email Notifications: Sends emails for new user registrations, password resets, and other significant events.
- Operations: Health checks and Prometheus metrics on a separate port, JSON logs with a trace id per request, an audit log of security events, OpenAPI documentation, a Docker image, and CI.

## Technologies Used

- Spring Boot: Main framework used for developing the application.
- Spring Security: Used for implementing security features like JWT, OAuth, and role-based access control.
- Redis: Holds the rate-limit counters, and nothing else.
- Thymeleaf: Template engine for processing email templates.
- MySQL: Relational database for storing user information and tokens, with Flyway migrations.
- Spring Boot Actuator and Micrometer: Health checks, metrics (Prometheus) and trace ids.
- springdoc-openapi: The OpenAPI description and Swagger UI.
- Docker and GitHub Actions: The container image, and the build and tests of every change.

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

[Mailpit](https://mailpit.axllent.org) is a fake mail server: in development, every email the app sends (verification links, OTPs) lands in its inbox at **http://localhost:8025** instead of a real mailbox. To send real emails from development instead, set `MAIL_HOST`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD` and `MAIL_FROM` (for Gmail, use an [App Password](https://support.google.com/accounts/answer/185833), not your account password).

#### Run the Application

```bash
./mvnw spring-boot:run
```

NOTE: The application will start at `http://localhost:8080`. The API is described at **http://localhost:8080/swagger-ui.html**, and health checks and metrics are on port `8081` (see "Operations").

### Configuration Profiles

| Profile | How it's selected | Settings come from |
|---|---|---|
| `dev` | the default | environment variables, then `./env.properties`, then defaults matching `docker-compose.yml`. SQL logging is on. |
| `prod` | `SPRING_PROFILES_ACTIVE=prod` (the Docker image's default) | environment variables only. There are no defaults for hosts or credentials: `DB_HOST`, `DB_DATABASE`, `DB_USER`, `DB_PASSWORD`, `REDIS_HOST`, `REDIS_PASSWORD`, `JWT_SECRET_KEY`, `MAIL_HOST`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_FROM` and `FRONTEND_URL` must be set; if one is missing, the app doesn't start and names all the missing ones. Logs are JSON, and the API docs are off. |

### Database Migrations

The schema is managed by [Flyway](https://documentation.red-gate.com/flyway). Migrations live in `src/main/resources/db/migration` and run automatically at startup. Hibernate only validates the schema (`ddl-auto: validate`), so every schema change must be a new migration file (`V10__...sql`, `V11__...sql`, ...). Never edit a migration that has already run.

### Running the Tests

```bash
./mvnw verify
```

The integration tests start real MySQL and Redis containers with [Testcontainers](https://testcontainers.com), so Docker must be running. They don't need `env.properties`, and they never send real emails.

## Operations

### Docker

```bash
docker build -t authcore .
```

The image runs the `prod` profile as a non-root user, so it needs the settings listed under "Configuration Profiles". The API listens on `8080`, and health checks and metrics on `8081`.

To try the image locally with MySQL, Redis and Mailpit (stop the app in your IDE first, it uses the same ports):

```bash
docker compose --env-file env.properties --profile app up -d --build
```

### Health Checks and Metrics

They're on a port of their own, `MANAGEMENT_PORT` (default `8081`), and need no login: **keep that port inside your network**, and don't route it through the reverse proxy. It must differ from `SERVER_PORT`.

| Endpoint | What it's for |
|---|---|
| `/actuator/health/liveness` | Is the app running? If not, restart it. |
| `/actuator/health/readiness` | Can it take requests? Needs the database. Not Redis: without it the app still works, without rate limits. |
| `/actuator/health` | Every check, up or down, without details |
| `/actuator/prometheus` | Metrics for [Prometheus](https://prometheus.io) |

Besides the usual JVM, HTTP and database pool metrics, the app counts:

| Metric | Counts |
|---|---|
| `authcore_audit_events_total{event, reason}` | every audit event, e.g. `event="LOGIN_FAILED", reason="WRONG_PASSWORD"` |
| `authcore_rate_limit_refused_total{limit}` | requests refused by a rate limit |
| `authcore_rate_limit_redis_failures_total` | Redis errors. Each one turns the rate limits off for a few seconds: worth an alert. |
| `authcore_emails_total{template, outcome}` | emails sent, or failed after 3 tries |

### Logs

- Every log line of a request has its trace id. A `500` answer names it (`"traceId"`), so its details can be found in the log.
- In `prod`, every line is a JSON object ([Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html)), for a log collector such as CloudWatch, Loki or Elasticsearch.
- **The audit log** is the logger `AUDIT`: one line per security event, with the user's id and address, never emails, passwords or tokens. For example `LOGIN_FAILED userId=12 ip=203.0.113.7 reason=WRONG_PASSWORD`. The events are `LOGIN_SUCCEEDED`, `LOGIN_FAILED`, `LOGOUT`, `SESSION_ENDED`, `ALL_SESSIONS_ENDED`, `REFRESH_TOKEN_REUSED`, `PASSWORD_RESET`, `ACCOUNT_DELETED`, `PASSWORD_CONFIRMATION_FAILED`, `USER_LOCKED`, `USER_UNLOCKED`, `USER_LOGGED_OUT` and `ROLE_CHANGED`.

### Cleanup

Every hour (`CLEANUP_CRON`, default `0 7 * * * *`), a job deletes expired sessions, used refresh tokens older than 7 days, and expired codes and links. Several servers can run it at once.

### Other Settings

| Setting | Default | |
|---|---|---|
| `DB_POOL_SIZE` | `10` | database connections per server; all servers together must stay below MySQL's `max_connections` |
| `API_DOCS_ENABLED` | `false` in `prod` | `/v3/api-docs` and Swagger UI |

### Sending Email with Amazon SES

The app sends over SMTP, so switching to [Amazon SES](https://aws.amazon.com/ses/) needs settings, not code:

1. In the AWS console, open SES in a region near your users (for example `ap-south-1`).
2. **Verify a sender:** an email address to start with, or your own domain.
3. New accounts are in the **sandbox**: they can only send to verified addresses, at a low rate. Verify your own inbox as a recipient to test. To email any user, request production access in the SES console.
4. Create **SMTP credentials** (SES → SMTP settings). They are not your AWS access keys.
5. Set:
   ```properties
   MAIL_HOST=email-smtp.<region>.amazonaws.com
   MAIL_PORT=587
   MAIL_USERNAME=<SES SMTP username>
   MAIL_PASSWORD=<SES SMTP password>
   MAIL_FROM=<the verified address, or one at the verified domain>
   FRONTEND_URL=<the web app's public URL: the links in the emails open it>
   ```
6. With your own domain, add the DNS records SES shows (**DKIM**), plus **SPF** and **DMARC**, so that the emails don't land in spam.

The rate limits and the one-minute wait between codes keep the app within SES's sending quota. `authcore_emails_total{outcome="failed"}` shows emails SES refused.

### Continuous Integration

GitHub Actions builds and tests every pull request and every push to `main` (`.github/workflows/ci.yml`), and checks that the Docker image builds. CodeQL looks for security problems in the code (free for public repositories), and Dependabot opens pull requests for new dependency versions.

## Project Structure

Packages under `com.authcore.auth` are grouped by feature:

| Package | What's in it |
|---|---|
| `auth` | registration, login, email verification, password reset |
| `user` | the user entity, roles, and the user repository |
| `user.account` | a user's own account: profile, account deletion (`/api/v1/users/me`) |
| `user.admin` | the admin API (`/api/v1/admin/users`), and the first admins from `AUTH_ADMIN_EMAILS` |
| `token` | the codes and links sent by email |
| `session` | sessions and refresh tokens, logout |
| `security` | Spring Security setup, access tokens (JWT) |
| `ratelimit` | limits on logins, code guesses and emails |
| `notification` | emails |
| `audit` | the audit log |
| `common` | settings, error handling, validation, cleanup, API docs |

## API Endpoints

### Authentication

| Endpoint | Body | What it does |
|---|---|---|
| `POST /api/v1/auth/register` | `firstName`, `lastName` (optional), `email`, `password` | Creates the account and emails a verification link |
| `POST /api/v1/auth/email-verification` | `email` | Emails a new verification link |
| `POST /api/v1/auth/email-verification/confirm` | `token` | Verifies the email with the token from the link |
| `POST /api/v1/auth/login` | `email`, `password` | Returns an access token, and sets the refresh token as a cookie |
| `POST /api/v1/auth/refresh` | (refresh cookie) | Returns a new access token, and replaces the refresh cookie |
| `POST /api/v1/auth/logout` | (refresh cookie) | Ends the session and deletes the cookie |
| `POST /api/v1/auth/password-reset` | `email` | Emails a reset code |
| `POST /api/v1/auth/password-reset/confirm` | `email`, `otp`, `password` | Sets the new password, and ends every session |

### The Logged-in User

These need the access token: `Authorization: Bearer <token>`.

| Endpoint | Body | What it does |
|---|---|---|
| `GET /api/v1/users/me` | | Returns the profile |
| `PATCH /api/v1/users/me` | `firstName`, `lastName` (both optional) | Changes what is given. An empty `lastName` removes it |
| `GET /api/v1/users/me/sessions` | | Lists where the user is logged in |
| `DELETE /api/v1/users/me/sessions/{id}` | | Logs that device out |
| `DELETE /api/v1/users/me/sessions` | | Logs out of all devices, this one too |
| `POST /api/v1/users/me/deletion` | | Emails a deletion code |
| `POST /api/v1/users/me/deletion/confirm` | `otp`, `password` | Deletes the account |

### Sessions and Tokens

- Every login opens a session. It ends after 7 days without use, 30 days after the login, or when the user logs out of it.
- The **access token** lasts 15 minutes. It names the user (`sub`), the session (`sid`), the user's token version (`ver`), the issuer (`iss`) and the audience (`aud`). Each request checks that the session still exists, so a logout works immediately.
- The **refresh token** is in an HttpOnly cookie and works once: every refresh sets a new one. If a used one shows up again, somebody has a copy of it, so all of the user's sessions end and they have to log in again.
- Two tabs may refresh at the same moment with the same cookie: for 10 seconds, the replaced token still returns an access token (but no new cookie).
- A password reset, "log out of all devices", and an admin locking the account end every session and make every access token stop working.
- The endpoints under `/api/v1/auth` ignore the `Authorization` header, so an expired access token doesn't get in the way of refreshing it.

### Rate Limits

Beyond a limit, the answer is `429` with the code `TOO_MANY_REQUESTS` and a `Retry-After` header (seconds).

| What | Limit |
|---|---|
| Wrong passwords (at login, and for admin actions) | 5 per account from one address in 15 minutes; 50 per account in an hour; 50 per address in 15 minutes |
| Registrations | 20 per address in an hour |
| Verification emails, password reset emails | 20 per address and 10 per account in an hour, each |
| Deletion emails | 10 per user in an hour |
| Confirming a verification link | 30 per address in 15 minutes |
| Confirming a password reset | 30 per address in 15 minutes; 10 per account from one address in an hour |

- "Account" is the email in the request, registered or not, so the limits don't show which emails are registered. A successful login or password reset clears the account's wrong passwords.
- The counters are in Redis. While Redis is down, nothing is limited, and everything else keeps working. Emailed codes always allow only 5 guesses.
- **Behind a reverse proxy, set `FORWARD_HEADERS_STRATEGY=native`**, or all users share the limits of the proxy's address. Without a proxy keep the default (`none`), or clients could make up their address.
- Locked out while testing? `docker compose exec redis redis-cli flushdb` clears the counters.

### Codes and Links

| Email | Contains | Valid for |
|---|---|---|
| Verify Email | a link to `FRONTEND_URL/verify-email?token=...` | 24 hours |
| Password Reset | an 8-digit code | 15 minutes |
| Delete Account | an 8-digit code | 10 minutes |

- The link opens a page of your web app (`FRONTEND_URL`, `http://localhost:3000` in development). That page must send the `token` to `POST /api/v1/auth/email-verification/confirm`. Without a web app, copy the token from the email in Mailpit and send it yourself:

  ```bash
  curl -X POST http://localhost:8080/api/v1/auth/email-verification/confirm \
    -H "Content-Type: application/json" -d '{"token": "..."}'
  ```
- A new code or link can be requested after 60 seconds, and replaces the old one. For the public endpoints, requests made sooner get the usual answer but send nothing; the deletion endpoint answers `409`.
- After 5 wrong guesses a code stops working. Request a new one.

### Input Rules

- **Passwords** (registration and reset): at least 12 characters and at most 72 bytes. bcrypt ignores anything after 72 bytes; accented letters and emoji take 2–4 bytes each.
- **Emails** are trimmed and lowercased, so `Jane@Example.com` and `jane@example.com` are the same account.
- **Invalid input** returns `400` with an `errors` object that maps each field to its problem, for example `{"password": "must be at least 12 characters"}`.

### Admin Endpoints

These need an access token of a user with the `ADMIN` role (otherwise `403`; without a token, `401`).

1. List users: `GET /api/v1/admin/users?page=0&size=20` (zero-based pages, at most 100 per page)
2. Get one user: `GET /api/v1/admin/users/{id}`

The actions that change something also need the admin's own password in the body, so a stolen access token isn't enough for them:

3. Lock a user: `POST /api/v1/admin/users/{id}/lock` with `{"password": "..."}`. Ends all their sessions, and refuses their logins (`ACCOUNT_LOCKED`) and password resets
4. Unlock a user: `POST /api/v1/admin/users/{id}/unlock` with `{"password": "..."}`
5. Log a user out of all devices: `POST /api/v1/admin/users/{id}/logout` with `{"password": "..."}`
6. Promote or demote a user: `PUT /api/v1/admin/users/{id}/role` with `{"role": "ADMIN", "password": "..."}` or `{"role": "USER", "password": "..."}`

A wrong password returns `403 WRONG_PASSWORD` (not `401`: the access token is still fine). Wrong passwords count like wrong passwords at login, with the same limits. The responses never include password hashes or tokens. Admins can't lock or demote themselves (`409 ADMIN_ACTION_REFUSED`).

#### Making someone an admin

Admins can promote other users (see above). For the first ones, list their emails in the `AUTH_ADMIN_EMAILS` setting (comma-separated):

- a listed email registers as `ADMIN`;
- existing users with a listed email are promoted when the application starts.

Removing an email from the list doesn't demote anyone. While an email is listed, its user can't be demoted over the API.

## Error Handling

Every error is a `ProblemDetail` ([RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)) with two extra properties: `code`, which never changes, and `msg`, a short text. Clients should decide by `code`.

```json
{
  "title": "Unauthorized",
  "status": 401,
  "detail": "The access token has expired.",
  "instance": "/api/v1/users/me",
  "code": "TOKEN_EXPIRED",
  "msg": "Token has expired"
}
```

| Status | Codes |
|---|---|
| 400 | `INVALID_INPUT` (with `errors`), `MALFORMED_BODY`, `MISSING_PARAMETER`, `INVALID_PARAMETER`, `MISSING_COOKIE`, `INVALID_CODE` (a code or link is wrong, expired or used), `BAD_REQUEST` |
| 401 | `AUTHENTICATION_REQUIRED` (no token), `INVALID_TOKEN`, `TOKEN_EXPIRED`, `INVALID_CREDENTIALS` |
| 403 | `ACCOUNT_DISABLED` (email not verified), `ACCOUNT_LOCKED` (by an admin), `ACCESS_DENIED`, `WRONG_PASSWORD` (an admin action's password) |
| 404 | `NOT_FOUND`, `USER_NOT_FOUND`, `SESSION_NOT_FOUND` |
| 405, 406, 415 | `METHOD_NOT_ALLOWED`, `NOT_ACCEPTABLE`, `UNSUPPORTED_MEDIA_TYPE` |
| 409 | `USER_ALREADY_EXISTS`, `TOKEN_ALREADY_EXISTS` (a code was sent less than a minute ago), `ADMIN_ACTION_REFUSED` |
| 429 | `TOO_MANY_REQUESTS` (see Rate Limits) |
| 500 | `INTERNAL_ERROR`, with the request's `traceId`. The details are only in the server log, under that trace id. |

## Contributing

Contributions are welcome! Please fork this repository and submit a pull request with your changes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
