Leco User Management Service (demo)
=================================

This is a scaffolded Spring Boot (Java 17) service for user management (registration, authentication, captcha/email verification stub, password reset).

Key choices and recommendations
- Database: This scaffold now uses an embedded in-memory MongoDB (Flapdoodle) for local development and demos. For production we recommend a managed MongoDB service or PostgreSQL depending on your needs:
	- Use PostgreSQL when you need strong relational constraints, transactions, and SQL queries.
	- Use MongoDB when you need a flexible document model and rapid schema evolution. The current implementation targets an in-memory MongoDB for easy local testing.
- Lombok: used to reduce boilerplate on entities/DTOs.
- JWT: used for stateless authentication tokens.

How to run (local development)
1. Ensure Java 17 and Maven are installed.
2. Create a PostgreSQL database and update `src/main/resources/application.yml` with URL/credentials (defaults point to `leco_usermgmt`).
3. Build and run:

```powershell
mvn -f backend\user-management-service clean package
mvn -f backend\user-management-service spring-boot:run
```

API endpoints (demo behavior)
- POST /auth/register – create a user (returns a mock JWT). Email verification token is generated and stored; email sending is a TODO.
- POST /auth/login – login and receive a JWT (requires enabled=true after verify-email).
- POST /auth/request-reset – trigger password reset (stores reset token; email sending is a TODO).
- POST /auth/verify-email – verify user email by token.
- POST /auth/verify-captcha – demo captcha validation (accepts any non-empty token).
 - POST /auth/register – create a user (returns a JWT). Email verification token is generated and stored and a verification email is attempted (requires SMTP configured).
 - POST /auth/login – login and receive a JWT (requires enabled=true after verify-email).
 - POST /auth/request-reset – trigger password reset (stores reset token and attempts to send reset email).
 - POST /auth/reset-password – complete password reset by passing `token` and `newPassword`.
 - POST /auth/verify-email – verify user email by token.
 - POST /auth/verify-captcha – demo captcha validation (accepts any non-empty token).

Protected endpoint
- GET /api/me – returns the profile for the authenticated user. Supply an `Authorization: Bearer <token>` header with the JWT received from `/auth/login`.

Roles and Admin
- Users have roles (e.g. `ROLE_ATTORNEY`, `ROLE_ADMIN`). The registration API accepts an optional `role` field (value `admin` to request admin). By default new users receive `ROLE_ATTORNEY`.
- Example admin-only endpoint: `GET /admin/users` — requires `ROLE_ADMIN`.
- To create an initial admin in local development, either register a user with `role: admin` (for demo) or seed the database.

Next steps
- Implement email sending for verification and reset (SMTP configuration already present in `application.yml`).
- Implement a proper JWT secret (use a secure 256-bit key) and rotate keys as necessary.
- Add integration tests and more secure token handling (expiry, refresh tokens).
