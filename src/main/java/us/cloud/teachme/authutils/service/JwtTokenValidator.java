package us.cloud.teachme.authutils.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import java.security.PublicKey;
import java.util.Date;

public class JwtTokenValidator {

    private final PublicKey publicKey;

    public JwtTokenValidator(PublicKey publicKeyPem) {
        this.publicKey = publicKeyPem;
    }

    /**
     * Validates the JWT token and returns the claims if valid.
     * Throws JwtException if the token is invalid or expired.
     */
    public Claims validateToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Checks if the token is expired based on the "exp" claim.
     */
    public boolean isTokenExpired(Claims claims) {
        Date expiration = claims.getExpiration();
        return expiration != null && expiration.before(new Date());
    }

    /**
     * Extracts user ID from the token claims.
     */
    public String getUserId(Claims claims) {
        return claims.getSubject();
    }

    /**
     * Extracts user role from the token claims.
     */
    public String getUserRole(Claims claims) {
        return claims.get("role", String.class);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
