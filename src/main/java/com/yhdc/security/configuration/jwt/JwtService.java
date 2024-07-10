package com.yhdc.security.configuration.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {


    @Value("${app.security.jwt.secret-key}")
    private String jwtSecretKey;

    @Value("${app.security.jwt.access.expiration}")
    private long accessJwtExpiration;

    @Value("${app.security.jwt.refresh.expiration}")
    private long refreshJwtExpiration;


    /**
     * Retrieve JWT from Header for Authentication
     *
     * @param request
     * @return String
     */
    public String extractJwtFromHeader(HttpServletRequest request) {
        String accessToken = request.getHeader("Authorization");
        if (accessToken != null && accessToken.startsWith("Bearer ")) {
            return accessToken.substring(7);
        } else {
            return null;
        }
    }


    /**
     * Retrieve User Email from JWT for Authentication
     *
     * @param token
     * @return String
     */
    public String extractUserEmailFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith(key())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }


    /**
     * Extract Subject from Claims
     *
     * @param token
     * @return String
     */
    public String extractSubjectFromJwtToken(String token) {
        return extractClaimFromJwtToken(token, Claims::getSubject);
    }

    /**
     * Generic method for extracting claims from subject
     *
     * @param token
     * @param claimsResolver
     * @param <T>
     * @return String
     */
    public <T> T extractClaimFromJwtToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extract Payload from JWT
     *
     * @param token
     * @return Claims
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(key())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Validate JWT
     *
     * @param token
     * @return boolean
     */
    public boolean validateJwtToken(String token, UserDetails userDetails) {
        try {
            Jwts.parser().verifyWith(key()).build().parseSignedClaims(token);
            final String username = extractUserEmailFromJwtToken(token);
            return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
        } catch (MalformedJwtException mfje) {
            // TODO: exception handling
        } catch (ExpiredJwtException eje) {
            // TODO: exception handling
        } catch (UnsupportedJwtException usje) {
            // TODO: exception handling
        } catch (IllegalArgumentException iae) {
            // TODO: exception handling
        }
        return false;
    }

    /**
     * Check JWT Expiration Date
     *
     * @param token
     * @return boolean
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Extract Expiration Date
     *
     * @param token
     * @return Date
     */
    private Date extractExpiration(String token) {
        return extractClaimFromJwtToken(token, Claims::getExpiration);
    }


    /**
     * Generate Access Token
     *
     * @param userClaims
     * @param userDetails
     * @return String
     */
    public String generateAccessToken(Map<String, Object> userClaims, UserDetails userDetails) {
        return generateToken(userClaims, userDetails, accessJwtExpiration);
    }


    /**
     * Generate Refresh Token
     *
     * @param userDetails
     * @return String
     */
    public String generateRefreshToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails, refreshJwtExpiration);
    }


    /**
     * Generates JWT Token
     *
     * @param userClaims
     * @param userDetails
     * @return String
     */
    public String generateToken(Map<String, Object> userClaims, UserDetails userDetails, long jwtExpiration) {
        String userEmail = userDetails.getUsername();
        return Jwts.builder()
                .claims(userClaims)
                .subject(userEmail)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(key())
                .compact();
    }


    /**
     * Generates a New JWT Secret Key
     *
     * @return SecretKey
     */
    private SecretKey key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecretKey));
    }


}
