package us.cloud.teachme.authutils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import us.cloud.teachme.authutils.service.JwtTokenValidator;

class JwtTokenValidatorTest {

    private JwtTokenValidator jwtTokenValidator;
    private String token;
    private String secretKey;

    @BeforeEach
    void setUp() throws Exception {
        // Generate a key pair for testing
        secretKey = "m56cYXCl2TxvV1/fwxLGziK5kVGT+kyOgMz7cIUdCjYuydbtvYXsLCIb2M4REzROggLh1zjEHKCu";

        jwtTokenValidator = new JwtTokenValidator(secretKey);
        long actualTime = System.currentTimeMillis();

        token = Jwts.builder()
                .subject("testUser")
                .claim("role", "ROLE_USER")
                .issuedAt(new Date(actualTime))
                .expiration(new Date(actualTime + 1000 * 60 * 10)) // 10 minutes expiration
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey)))
                .compact();

    }

    @Test
    void testValidateToken() {
        Claims claims = jwtTokenValidator.validateToken(token);
        assertEquals("testUser", claims.getSubject());
        assertEquals("ROLE_USER", claims.get("role"));
    }

    @Test
    void testIsTokenExpired() {
        Claims claims = jwtTokenValidator.validateToken(token);
        assertFalse(jwtTokenValidator.isTokenExpired(claims));
        long actualTime = System.currentTimeMillis();

        String expiredToken = Jwts.builder()
                .subject("testUser")
                // Already expired datetime
                .issuedAt(new Date(actualTime))
                .expiration(new Date(actualTime - 1000))
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey)))
                .compact();

        assertThrows(ExpiredJwtException.class, () -> jwtTokenValidator.validateToken(expiredToken));
    }
}
