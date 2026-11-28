# Authentication System

This project is a comprehensive authentication system built using Spring Boot. It covers registration with email verification, login with JWT access tokens, password reset and account deletion with emailed codes, and email notifications. The system is designed following best practices, including SOLID principles, DRY, and design patterns for flexibility and scalability. It also includes role-based access control to manage user permissions.

## Features

- Password Hashing: Argon2id (OWASP's settings). Older bcrypt hashes still work and are replaced at the user's next login.
- JWT Authentication: Short-lived access tokens (JWT, 15 minutes) that stop working at once after a logout, a password reset or a password change.
- Sessions: One session per device, with refresh tokens that work once and are stored only as hashes. Users can list their sessions and log out of them.
- Rate Limiting: Limits on wrong passwords, code guesses, registrations and emails.
- Role-Based Access Control: Different roles for users to manage access to various parts of the application.
- Emailed Codes and Links: Verify an email, reset a password, change the email or delete an account. They are stored only as hashes, work once, expire, and stop working after 5 wrong guesses.
- Change Email: The new address is confirmed with a code; the old one gets a link that changes it back for 7 days.
- Two-Factor Authentication: Optional codes from an authenticator app (TOTP) at every login, with recovery codes. The secrets are encrypted.
- Sign in with Google: Optional, with OpenID Connect. Accounts are matched by Google's id, or by a verified email the first time.
- Security Emails: The owner is told about a login from a new device, a password change or reset, an email change, two-factor authentication turned on or off, a used recovery code, and a copied refresh token, with when and from where.
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

And `TOTP_ENCRYPTION_KEY`, which encrypts the two-factor secrets: a base64 key of exactly 32 bytes. Generate one with `openssl rand -base64 32`, and keep it (see Two-Factor Authentication).

`GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` are optional: without them, there is no Google sign-in (see Signing in with Google).

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
| `prod` | `SPRING_PROFILES_ACTIVE=prod` (the Docker image's default) | environment variables only. There are no defaults for hosts or credentials: `DB_HOST`, `DB_DATABASE`, `DB_USER`, `DB_PASSWORD`, `REDIS_HOST`, `REDIS_PASSWORD`, `JWT_SECRET_KEY`, `TOTP_ENCRYPTION_KEY`, `MAIL_HOST`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_FROM` and `FRONTEND_URL` must be set; if one is missing, the app doesn't start and names all the missing ones. Logs are JSON, and the API docs are off. |

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
- **The audit log** is the logger `AUDIT`: one line per security event, with the user's id and address, never emails, passwords or tokens. For example `LOGIN_FAILED userId=12 ip=203.0.113.7 reason=WRONG_PASSWORD`. The events are `LOGIN_SUCCEEDED`, `LOGIN_FAILED`, `LOGOUT`, `SESSION_ENDED`, `ALL_SESSIONS_ENDED`, `REFRESH_TOKEN_REUSED`, `PASSWORD_RESET`, `PASSWORD_CHANGED`, `EMAIL_CHANGED`, `EMAIL_CHANGE_UNDONE`, `SECOND_FACTOR_REQUIRED`, `TWO_FACTOR_ENABLED`, `TWO_FACTOR_DISABLED`, `RECOVERY_CODES_RENEWED`, `GOOGLE_SIGN_UP`, `GOOGLE_LINKED`, `ACCOUNT_DELETED`, `PASSWORD_CONFIRMATION_FAILED`, `USER_LOCKED`, `USER_UNLOCKED`, `USER_LOGGED_OUT` and `ROLE_CHANGED`.

### Cleanup

Every hour (`CLEANUP_CRON`, default `0 7 * * * *`), a job deletes expired sessions, used refresh tokens older than 7 days, expired codes and links, and devices not seen for 90 days. Several servers can run it at once.

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
| `auth` | registration, login, email verification, password reset, undoing an email change |
| `user` | the user entity, roles, and the user repository |
| `user.account` | a user's own account: profile, password and email change, account deletion (`/api/v1/users/me`) |
| `user.admin` | the admin API (`/api/v1/admin/users`), and the first admins from `AUTH_ADMIN_EMAILS` |
| `token` | the codes and links sent by email |
| `session` | sessions and refresh tokens, logout |
| `security` | Spring Security setup, access tokens (JWT) |
| `mfa` | two-factor authentication: TOTP, recovery codes, the login's second step |
| `social` | signing in with Google |
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
| `POST /api/v1/auth/login` | `email`, `password` | Returns an access token, and sets the refresh token as a cookie. With two-factor authentication, returns a `challenge` instead |
| `POST /api/v1/auth/login/2fa` | `challenge`, `code` | The second step of a login with two-factor authentication: returns what a login returns |
| `GET /api/v1/auth/oauth2/authorization/google` | | Sends the browser to Google (only with `GOOGLE_CLIENT_ID`) |
| `POST /api/v1/auth/oauth2/exchange` | `code` | After signing in with Google: returns what a login returns |
| `POST /api/v1/auth/refresh` | (refresh cookie) | Returns a new access token, and replaces the refresh cookie |
| `POST /api/v1/auth/logout` | (refresh cookie) | Ends the session and deletes the cookie |
| `POST /api/v1/auth/password-reset` | `email` | Emails a reset code |
| `POST /api/v1/auth/password-reset/confirm` | `email`, `otp`, `password` | Sets the new password, and ends every session |
| `POST /api/v1/auth/email-change/undo` | `token`, `password` | From the link sent to the old address: changes the email back, sets the new password, and ends every session |

### The Logged-in User

These need the access token: `Authorization: Bearer <token>`.

| Endpoint | Body | What it does |
|---|---|---|
| `GET /api/v1/users/me` | | Returns the profile |
| `PATCH /api/v1/users/me` | `firstName`, `lastName` (both optional) | Changes what is given. An empty `lastName` removes it |
| `PUT /api/v1/users/me/password` | `currentPassword`, `newPassword` | Changes the password and logs out of all other devices. Returns a new `accessToken` for this device (the old one stops working); the refresh cookie stays the same |
| `POST /api/v1/users/me/email` | `currentPassword`, `newEmail` | Emails a code to the new address. Nothing changes yet |
| `POST /api/v1/users/me/email/confirm` | `otp` | Changes the email to the address the code was sent to. Every device stays logged in |
| `GET /api/v1/users/me/2fa` | | Whether two-factor authentication is on, and how many recovery codes are left |
| `POST /api/v1/users/me/2fa/setup` | `currentPassword` | Returns a new `secret` and `otpauthUri` for the app |
| `POST /api/v1/users/me/2fa/enable` | `code` | Turns it on with the app's first code. Returns 10 `recoveryCodes` |
| `POST /api/v1/users/me/2fa/disable` | `currentPassword`, `code` | Turns it off |
| `POST /api/v1/users/me/2fa/recovery-codes` | `currentPassword`, `code` | Returns 10 new `recoveryCodes`; the old ones stop working |
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
- A password change ends every *other* session. Every access token stops working, so the answer has a new one for this session.
- An email change keeps every session (access tokens name the user by id, not by email). Undoing one ends them all.
- The endpoints under `/api/v1/auth` ignore the `Authorization` header, so an expired access token doesn't get in the way of refreshing it.

### Rate Limits

Beyond a limit, the answer is `429` with the code `TOO_MANY_REQUESTS` and a `Retry-After` header (seconds).

| What | Limit |
|---|---|
| Wrong passwords (at login, for a password change, and for admin actions) | 5 per account from one address in 15 minutes; 50 per account in an hour; 50 per address in 15 minutes |
| Registrations | 20 per address in an hour |
| Verification emails, password reset emails | 20 per address and 10 per account in an hour, each |
| Deletion emails | 10 per user in an hour |
| Email change codes | 10 per user in an hour |
| Confirming a verification link | 30 per address in 15 minutes |
| Confirming a password reset | 30 per address in 15 minutes; 10 per account from one address in an hour |
| Undoing an email change | 30 per address in 15 minutes |
| Two-factor codes at login | 30 per address in 15 minutes; 5 wrong in a row per account, then 15 minutes without checks |
| Exchanging a Google sign-in's code | 30 per address in 15 minutes |

- "Account" is the email in the request, registered or not, so the limits don't show which emails are registered. A successful login, password reset or password change clears the account's wrong passwords.
- The counters are in Redis. While Redis is down, nothing is limited, and everything else keeps working. Emailed codes always allow only 5 guesses.
- **Behind a reverse proxy, set `FORWARD_HEADERS_STRATEGY=native`**, or all users share the limits of the proxy's address. Without a proxy keep the default (`none`), or clients could make up their address.
- Locked out while testing? `docker compose exec redis redis-cli flushdb` clears the counters.

### Security Emails

These tell the owner that something happened to their account, with the time (UTC), the address and the device (its User-Agent). They can't be turned off.

| Subject | When |
|---|---|
| New sign-in to your AuthCore account | A login from a device the account hasn't used in the last 90 days |
| Your AuthCore password was changed | `PUT /api/v1/users/me/password` |
| Your AuthCore password was reset | A password reset with an emailed code |
| You were logged out of AuthCore everywhere | A used refresh token showed up again, so every session ended |
| Your AuthCore email was changed | The email was changed (sent to the old address, with the undo link; see below) |
| Two-factor authentication is on for your AuthCore account | It was turned on |
| Two-factor authentication is off for your AuthCore account | It was turned off, by the user or by an admin |
| A recovery code was used to sign in to AuthCore | A login with a recovery code |
| Google sign-in was added to your AuthCore account | The first sign-in with Google to an existing account |

- **Devices** are told apart by the `deviceId` cookie (HttpOnly, path `/api/v1/auth`, 90 days), which every login sets. It stays after a logout. Only its hash is stored (`known_devices`).
- The first login of an account created less than a day ago sends nothing: it's the owner, right after signing up.
- A client that doesn't keep cookies (e.g. a script or a mobile app without a cookie store) counts as a new device at every login. Apps should keep the `deviceId` cookie like a browser does.

### Codes and Links

| Email | Contains | Valid for |
|---|---|---|
| Verify Email | a link to `FRONTEND_URL/verify-email?token=...` | 24 hours |
| Password Reset | an 8-digit code | 15 minutes |
| Delete Account | an 8-digit code | 10 minutes |
| Confirm your new AuthCore email | an 8-digit code, sent to the new address | 15 minutes |
| Your AuthCore email was changed | a link to `FRONTEND_URL/undo-email-change?token=...`, sent to the old address | 7 days |

- The link opens a page of your web app (`FRONTEND_URL`, `http://localhost:3000` in development). That page must send the `token` to `POST /api/v1/auth/email-verification/confirm`. Without a web app, copy the token from the email in Mailpit and send it yourself:

  ```bash
  curl -X POST http://localhost:8080/api/v1/auth/email-verification/confirm \
    -H "Content-Type: application/json" -d '{"token": "..."}'
  ```
- A new code or link can be requested after 60 seconds, and replaces the old one. For the public endpoints, requests made sooner get the usual answer but send nothing; the deletion endpoint answers `409`.
- After 5 wrong guesses a code stops working. Request a new one.

### Changing the Email

1. `POST /api/v1/users/me/email` with the current password and the new address. The new address gets a code. An address that another account has is refused (`409 USER_ALREADY_EXISTS`), like at registration.
2. `POST /api/v1/users/me/email/confirm` with the code. The account now has the new address, every device stays logged in, and reset or deletion codes sent to the old address stop working.
3. The old address gets a link that changes the email back for 7 days. Whoever knew the password could otherwise take the account, since reset codes now go to their address. The link's page (`FRONTEND_URL/undo-email-change`) must send the `token` and a new password to `POST /api/v1/auth/email-change/undo`, which changes the email back, sets the password and ends every session.

While that link works, the email can't be changed again (`409 EMAIL_CHANGE_REFUSED`), and no other account can register or change to the old address. That also means that whoever can read the old inbox can take the account back during those 7 days.

### Input Rules

- **Passwords** (registration, reset, change, and undoing an email change): at least 12 characters and at most 72 bytes; accented letters and emoji take 2–4 bytes each. The limit comes from bcrypt, which ignores anything after 72 bytes; new hashes are Argon2id, but passwords from before are still checked with bcrypt.
- **Password hashes** are Argon2id (19 MiB of memory, 2 iterations, 1 lane: OWASP's minimum), stored as `{argon2}$argon2id$...`. Hashes from before have no prefix and are bcrypt; they still match, and are replaced with Argon2id at the user's next login with the right password (sessions stay). Each hash takes 19 MiB, so no more run at once than the server has processors; the others wait.
- **Emails** are trimmed and lowercased, so `Jane@Example.com` and `jane@example.com` are the same account.
- **Invalid input** returns `400` with an `errors` object that maps each field to its problem, for example `{"password": "must be at least 12 characters"}`.

### Two-Factor Authentication

Optional for every user: an authenticator app (Google Authenticator, Authy, 1Password, ...) gives a 6-digit code every 30 seconds (TOTP, RFC 6238), and every login needs one after the password.

**Turning it on**

1. `POST /api/v1/users/me/2fa/setup` with the current password. The answer has the `secret` (to type into the app) and the `otpauthUri` (for the app to scan as a QR code; the frontend draws it). Nothing changes at login yet.
2. `POST /api/v1/users/me/2fa/enable` with the first `code` the app shows. Two-factor authentication is on, and the answer has 10 **recovery codes** (`xxxxx-xxxxx`), shown this once. Each works once instead of a code from the app.

**Logging in**

1. `POST /api/v1/auth/login` with the email and password. Instead of tokens, the answer is `{"secondFactorRequired": true, "challenge": "..."}`, and no cookies are set.
2. `POST /api/v1/auth/login/2fa` with the `challenge` and the `code` (from the app, or a recovery code). The answer is the same as a normal login's: the access token, and the refresh and device cookies.

- The challenge lasts 5 minutes. A password change or reset, a lock, or "log out of all devices" meanwhile makes it useless (`401 TWO_FACTOR_LOGIN_EXPIRED`): log in again.
- A wrong code is `401 INVALID_CREDENTIALS`, like a wrong password. After 5 wrong codes in a row, none is checked for 15 minutes (`429`). That limit is kept in the database, so it holds while Redis is down.
- A code works once. The app's clock may be 30 seconds off either way.
- Using a recovery code emails the owner.

**Turning it off, new recovery codes**

- `POST /api/v1/users/me/2fa/disable` and `POST /api/v1/users/me/2fa/recovery-codes` need the current password and a code (from the app, or a recovery code). New recovery codes replace the old ones.
- A user who lost both their phone and their recovery codes asks an admin: `POST /api/v1/admin/users/{id}/2fa/disable` (see Admin Endpoints).
- A password reset doesn't turn it off.

**The secrets** are encrypted in the database (AES-256-GCM) with `TOTP_ENCRYPTION_KEY`, and recovery codes are stored as keyed hashes. **Keep the key:** if it changes or is lost, nobody's app codes or recovery codes work any more, and an admin has to turn two-factor authentication off for each of those users.

### Signing in with Google

Optional: on when `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` are set (a "Web application" OAuth client in the Google Cloud console). Register this redirect URI there: `https://<api host>/api/v1/auth/oauth2/callback/google`.

1. The web app sends the browser to `GET /api/v1/auth/oauth2/authorization/google` (a navigation, not `fetch`). The API sends it on to Google.
2. Google sends it back to the API's callback, which sends it to the web app's page `FRONTEND_URL/login/google`, with `#code=...` in the fragment, or `#error=...`.
3. That page sends the `code` to `POST /api/v1/auth/oauth2/exchange` (with `credentials: "include"`). The answer is a login's: the access token and the cookies, or `secondFactorRequired` and a `challenge` for a user with two-factor authentication.

- The code works once, for one minute. It's in the fragment, so it's never sent to a server or in a `Referer`.
- Between steps 1 and 2, the state, nonce and PKCE verifier are in an encrypted, HttpOnly cookie (`SameSite=Lax`, 5 minutes). The API keeps no server sessions, so any of several servers can take the callback.
- A Google account is known by its id, not its email: it goes on signing in to the same account after an email change.
- **The first time**, only an email Google says is verified is used:
  - no account has it: a new one is made, verified, with the name from Google and no password anyone knows. "Forgot password" sets one, which is needed to change the email, turn on two-factor authentication or delete the account;
  - a verified account has it: Google is linked to it, and the owner gets an email;
  - an unverified account has it: it's taken over. Its password is replaced, since anyone could have registered it with that address.
- Errors in the fragment: `EMAIL_NOT_VERIFIED`, `ACCOUNT_LOCKED`, `OTHER_GOOGLE_ACCOUNT` (the account with this email is linked to another Google account), `EMAIL_UNAVAILABLE` (an email change can still be undone to this address), `GOOGLE_SIGN_IN_FAILED` (cancelled at Google, or the request was too old or changed).
- Only Google's ID token is used; Google's access token isn't kept.

### Admin Endpoints

These need an access token of a user with the `ADMIN` role (otherwise `403`; without a token, `401`).

1. List users: `GET /api/v1/admin/users?page=0&size=20` (zero-based pages, at most 100 per page)
2. Get one user: `GET /api/v1/admin/users/{id}`

The actions that change something also need the admin's own password in the body, so a stolen access token isn't enough for them:

3. Lock a user: `POST /api/v1/admin/users/{id}/lock` with `{"password": "..."}`. Ends all their sessions, and refuses their logins (`ACCOUNT_LOCKED`) and password resets
4. Unlock a user: `POST /api/v1/admin/users/{id}/unlock` with `{"password": "..."}`
5. Log a user out of all devices: `POST /api/v1/admin/users/{id}/logout` with `{"password": "..."}`
6. Promote or demote a user: `PUT /api/v1/admin/users/{id}/role` with `{"role": "ADMIN", "password": "..."}` or `{"role": "USER", "password": "..."}`
7. Turn a user's two-factor authentication off: `POST /api/v1/admin/users/{id}/2fa/disable` with `{"password": "..."}`, for a user who lost both their phone and their recovery codes. Emails the user. Check who is asking first: this lets the password alone into the account.

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
| 401 | `AUTHENTICATION_REQUIRED` (no token), `INVALID_TOKEN`, `TOKEN_EXPIRED`, `INVALID_CREDENTIALS` (also a wrong two-factor code at login), `TWO_FACTOR_LOGIN_EXPIRED` (log in again) |
| 403 | `ACCOUNT_DISABLED` (email not verified), `ACCOUNT_LOCKED` (by an admin), `ACCESS_DENIED`, `WRONG_PASSWORD` (the current password of a password change, or an admin action's password) |
| 404 | `NOT_FOUND`, `USER_NOT_FOUND`, `SESSION_NOT_FOUND` |
| 405, 406, 415 | `METHOD_NOT_ALLOWED`, `NOT_ACCEPTABLE`, `UNSUPPORTED_MEDIA_TYPE` |
| 409 | `USER_ALREADY_EXISTS`, `TOKEN_ALREADY_EXISTS` (a code was sent less than a minute ago), `ADMIN_ACTION_REFUSED`, `EMAIL_CHANGE_REFUSED`, `TWO_FACTOR_ALREADY_ENABLED`, `TWO_FACTOR_NOT_SET_UP`, `TWO_FACTOR_NOT_ENABLED` |
| 429 | `TOO_MANY_REQUESTS` (see Rate Limits) |
| 500 | `INTERNAL_ERROR`, with the request's `traceId`. The details are only in the server log, under that trace id. |

## Contributing

Contributions are welcome! Please fork this repository and submit a pull request with your changes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
