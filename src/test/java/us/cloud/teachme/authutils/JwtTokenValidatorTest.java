package us.cloud.teachme.authutils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenValidatorTest {

    private JwtTokenValidator jwtTokenValidator;
    private String token;
    private PrivateKey privateKey;

    @BeforeEach
    void setUp() throws Exception {
        // Generate a key pair for testing
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        jwtTokenValidator = new JwtTokenValidator(publicKey);

        token = Jwts.builder()
                .setSubject("testUser")
                .claim("role", "ROLE_USER")
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 10)) // 10 minutes expiration
                .signWith(privateKey, SignatureAlgorithm.RS256)
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

        String expiredToken = Jwts.builder()
                .setSubject("testUser")
                // Already expired datetime
                .setExpiration(new Date(System.currentTimeMillis() - 1000))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();

        assertThrows(ExpiredJwtException.class, () -> jwtTokenValidator.validateToken(expiredToken));
    }
}
