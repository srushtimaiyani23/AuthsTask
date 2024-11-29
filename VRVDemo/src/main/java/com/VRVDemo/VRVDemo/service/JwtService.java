package com.VRVDemo.VRVDemo.service;

import com.VRVDemo.VRVDemo.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {

    private final String SECRET_KEY = "34f98bbb13d009d6dd0b0fd8eda47235ab8a9b9c0bca9526a64ea2063a8292fd";

            public String extractUsername(String token)
            {
                return extractClaim(token, Claims::getSubject);
            }

            public boolean isValid(String token, UserDetails user)
            {
                String username = extractUsername(token);
                return (username.equals(user.getUsername())) && !isTokenExpired(token);
            }

            public <T> T extractClaim(String token, Function<Claims, T> resolver){
                Claims claims = extraAllClaims(token);
                return resolver.apply(claims);
            }

           public boolean isTokenExpired(String token)
           {
               return extractExpiration(token).before(new Date());
           }

           private Date extractExpiration(String token)
           {
               return extractClaim(token,Claims::getExpiration);
           }

    private Claims extraAllClaims(String token)
    {
        return Jwts
                .parser()
                .verifyWith(getSignKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

    }
            public String generateToken(User user)
            {
                String token = Jwts.builder()
                        .subject(user.getUsername())
                        .issuedAt(new Date(System.currentTimeMillis()))
                        .expiration(new Date(System.currentTimeMillis() + 24+60+60+1000 ))
                        .signWith(getSignKey())
                        .compact();
                return token;
            }
            private SecretKey getSignKey()
            {
                byte[] keyBytes = Decoders.BASE64URL.decode(SECRET_KEY);
                return Keys.hmacShaKeyFor(keyBytes);
            }
}
