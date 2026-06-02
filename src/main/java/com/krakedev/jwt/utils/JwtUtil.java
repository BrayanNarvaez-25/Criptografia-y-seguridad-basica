package com.krakedev.jwt.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtil {

    private static final String SECRET_KEY = "patitas_al_rescate_clave_secreta_2024";
    private static final long EXPIRATION_MS = 30 * 60 * 1000L; // 30 minutos

    public String generarToken(String username, String rol) {
        return JWT.create()
                .withSubject(username)
                .withClaim("rol", rol)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_MS))
                .sign(Algorithm.HMAC256(SECRET_KEY));
    }

    public DecodedJWT verificarToken(String token) throws JWTVerificationException {
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SECRET_KEY))
                .build();
        return verifier.verify(token);
    }

    public String obtenerUsername(String token) {
        return verificarToken(token).getSubject();
    }

    public String obtenerRol(String token) {
        return verificarToken(token).getClaim("rol").asString();
    }
}