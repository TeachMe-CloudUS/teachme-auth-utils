package us.cloud.teachme.authutils.service;

import java.util.Date;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

public class JwtTokenValidator {

    private final String secretKey;

    public JwtTokenValidator(String secretKey) {
        this.secretKey = secretKey;
    }

    /**
     * Validates the JWT token and returns the claims if valid.
     * Throws JwtException if the token is invalid or expired.
     */
    public Claims validateToken(String token) {
        return Jwts.parser().verifyWith(getSignKey()).build().parseSignedClaims(token).getPayload();
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


    private SecretKey getSignKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
    }

}
