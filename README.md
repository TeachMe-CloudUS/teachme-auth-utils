# teachme-auth-utils

`teachme-auth-utils` is a Java library providing JWT-based authentication utilities for microservices within the `teachme` platform. It includes classes and filters to validate JWTs, handle authorization, and simplify token-based security configurations in Spring Boot applications.

## Features

- JWT validation, including expiration checks and claim extraction
- `JwtAuthenticationFilter` to secure specific API endpoints based on JWT presence and validity

## Getting Started

### Prerequisites

- Java 17 or higher
- Spring Boot 3.x

### Installation

Add the library as a dependency in your project’s `pom.xml`:

```xml
<dependency>
    <groupId>us.cloud.teachme</groupId>
    <artifactId>teachme-auth-utils</artifactId>
    <version>0.0.2-SNAPSHOT</version>
</dependency>
```

Then, add the repository where the library is hosted in your `pom.xml`:

```xml
<repositories>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/TeachMe-CloudUS/teachme-auth-utils</url>
    </repository>
</repositories>
```

Finally, add your GitHub username and a personal access token to your `~/.m2/settings.xml` file:

```xml
<settings>
    <servers>
        <server>
            <id>github</id>
            <username>{GITHUB_USERNAME}</username>
            <password>{GITHUB_TOKEN}</password>
        </server>
    </servers>
</settings>
```

### Configuration

To use the library, configure the following properties in `application.properties`:

```properties
# Path to the RSA public key used for JWT verification
security.jwt.secret-key=SECRET_KEY

# Paths that require authentication
security.jwt.protected-paths=/api/protected/*

# Paths that don't require authentication
security.jwt.white-listed-paths=/api/public/*
```

### Usage

To register `AuthSecurityConfiguration`, import `JwtFilterConfig` in your Spring configuration:

```java
package us.cloud.teachme.yourservice;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import us.cloud.teachme.authutils.config.AuthSecurityConfiguration;

@Configuration
@Import(AuthSecurityConfiguration.class)
public class SecurityConfig {

}
```
