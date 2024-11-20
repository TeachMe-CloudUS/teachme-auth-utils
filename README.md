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

### Configuration
To use the library, configure the following properties in `application.properties`:

```properties
# Path to the RSA public key used for JWT verification
jwt.public-key.path=classpath:public-key.pem

# Paths that require authentication
jwt.protected-paths=/api/protected/*
```

### Usage
To register `JwtAuthenticationFilter`, import `JwtFilterConfig` in your Spring configuration:

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