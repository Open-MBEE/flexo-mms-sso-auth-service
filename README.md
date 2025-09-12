# Flexo MMS SSO Authentication Service

A Spring Boot microservice that provides authentication services for the Flexo Model Management System (MMS). This service supports OAuth2/OIDC authentication, API key management, and JWT generation.

## Features

- OAuth2/OIDC authentication integration
- API key management for service-to-service communication
- JWT token generation and validation
- User profile information retrieval
- Database support for both SQLite (development) and PostgreSQL (production)

## Quickstart

### Prerequisites

- Java 17 or higher
- Gradle 7.6+ (or use the included Gradle wrapper)
- SQLite for development or PostgreSQL for production

### Running Locally

1. Clone the repository:
   ```bash
   git clone https://github.com/Open-MBEE/flexo-mms-sso-auth-service.git
   cd flexo-mms-sso-auth-service
   ```

2. Build the project:
   ```bash
   ./gradlew build
   ```

3. Run the application:
   ```bash
   ./gradlew bootRun
   ```

The service will be available at http://localhost:3000.

### Configuration

The application can be configured through `application.yml`. Key configuration options:

```yaml
spring:
  datasource:
    url: jdbc:sqlite:sso-database.db # NOTE: This requires a writeable mount
    # For PostgreSQL use:
    # url: jdbc:postgresql://localhost:5432/sso_db
    # username: your_username
    # password: your_password
  security:
    oauth2:
      client:
        registration:
          oidc:
            client-id: your-client-id
            client-secret: your-client-secret
            redirect_uri: http://localhost:3000/login/oauth2/code/oidc
        provider:
          oidc:
            issuer-uri: https://your-identity-provider/
```

## Docker Support

### Pull the Docker Image

```bash
docker pull openmbee/flexo-mms-sso-auth-service:latest
```

### Building the Docker Image

Build the Docker image with:

```bash
docker build -t flexo-mms-sso-auth-service .
```

### Running with Docker Compose

A `docker-compose.yml` file is provided for easy deployment:

```bash
docker-compose up
```

This will start both the SSO service and a mock OIDC server for testing.

### Environment Variables

When running with Docker, you can override settings with environment variables:

```bash
docker run -p 8080:8080 \
  -e SPRING_PROFILES_ACTIVE=docker \
  -e SPRING_DATASOURCE_URL=jdbc:postgresql://db:5432/sso_db \
  -e SPRING_DATASOURCE_USERNAME=postgres \
  -e SPRING_DATASOURCE_PASSWORD=password \
  -e SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_OIDC_CLIENT_ID=your-client-id \
  -e SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_OIDC_CLIENT_SECRET=your-client-secret \
  -e SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_OIDC_ISSUER_URI=https://your-identity-provider/ \
  -e FLEXO_SSO_AUTH_SERVICE_SSO_USER_ID_FIELD: username \
  -e FLEXO_SSO_AUTH_SERVICE_SSO_GROUP_CLAIMS_FIELD: groups \
  flexo-mms-sso-auth-service
```

## Setting Up SSO

### Configuring an OIDC Provider

1. Register an application with your OIDC provider (Auth0, Okta, Keycloak, etc.)
2. Configure the callback URL: `http://your-service-domain/login/oauth2/code/oidc`
3. Update `application.yml` or environment variables with:
   - Client ID
   - Client Secret
   - Issuer URI

### User Claims and Group Mapping

The service maps OIDC claims to user information and groups:

```yaml
flexo:
  sso-auth-service:
    sso_user_id_field: "sub"
    jwt_user_id_field: "preferred_username"
    group_claims_field: "groups"
```

- `sso_user_id_field`: Field in the ID token used as the primary user identifier
- `jwt_user_id_field`: Field to use as the username in issued JWTs (Typically the same as sso_user_id_field)
- `group_claims_field`: Field containing user groups/roles

## API Endpoints

### Authentication Endpoints

- `GET /login`: Initiates OIDC authentication flow
- `GET /login?apiKey={key}`: Authenticates using an API key
- `GET /check`: Validates the current authentication
- `GET /api/userinfo`: Returns information about the current user

### API Key Management

Navigate to http://your-service-domain/user in order to manage and create API keys

## Advanced Configuration

### Custom Context Path
It is possible to serve this application on a url prefix, i.e. from a reverse proxy. Simply define the environment variable as follows:

```bash
export SERVER_SERVLET_CONTEXT_PATH=/sso
```
Ensure that the given string begins with a "/" and ends without the trailing "/".

## Development

### Running Tests

```bash
./gradlew test
```

## License

This project is licensed under the Apache License 2.0.