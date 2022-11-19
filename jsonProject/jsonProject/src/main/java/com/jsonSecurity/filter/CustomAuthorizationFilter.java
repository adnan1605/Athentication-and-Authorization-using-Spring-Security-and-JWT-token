package com.jsonSecurity.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.http.parser.Authorization;
import org.aspectj.lang.annotation.DeclareError;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter{
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getServletPath().equals("/api/login")|| request.getServletPath().equals("/api/refresh/token"))
            filterChain.doFilter(request,response);
        else {

                String authorizationHeader = request.getHeader(AUTHORIZATION);
                if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                    try {
                        String token = authorizationHeader.substring("Bearer ".length());
                        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                        JWTVerifier verfier = JWT.require(algorithm).build();
                        DecodedJWT decodedJWT = verfier.verify(token);
                        String username = decodedJWT.getSubject();
                        String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
                        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                        Arrays.stream(roles).forEach(role -> {
                            authorities.add(new SimpleGrantedAuthority(role));
                        });
                        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                                new UsernamePasswordAuthenticationToken(username, null, authorities);
                        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                        filterChain.doFilter(request, response);

                    } catch (Exception exception) {
                        log.error("Error in :{}",exception.getMessage());
                        response.setHeader("error", exception.getMessage());
                        response.setStatus(FORBIDDEN.value());
                        //response.sendError(FORBIDDEN.value());
                        HashMap<String,String> error=new HashMap<>();
                        response.setContentType(APPLICATION_JSON_VALUE);
                        error.put("error_message",exception.getMessage());
                        new ObjectMapper().writeValue(response.getOutputStream(),error);
                    }
                }
                else{
                    filterChain.doFilter(request,response);

                }
        }
    }
}
