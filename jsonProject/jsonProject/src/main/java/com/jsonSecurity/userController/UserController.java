package com.jsonSecurity.userController;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jsonSecurity.model.Role;
import com.jsonSecurity.model.User;
import com.jsonSecurity.service.UserService;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping(value="/api")
@Slf4j
public class UserController {
    @Autowired
    UserService userService;

    @GetMapping(value="/getUser")
    ResponseEntity<List<User>> getUsers(){
        return ResponseEntity.ok().body(userService.getUsers());
    }

    @PostMapping("/user/save")
    ResponseEntity<User>saveUser(@RequestBody User user){
        return ResponseEntity.ok().body(userService.saveUser(user));
    }

    @PostMapping("/role/save")
    ResponseEntity<Role>saveUser(@RequestBody Role role){
        return ResponseEntity.ok().body(userService.saveRole(role));
    }

    @PostMapping("/role/addRoleToUser")
    ResponseEntity<?>addRoleToUser(@RequestBody RoleForm roleForm){
        userService.addRoleToUser(roleForm.getUsername(), roleForm.getRole());
        return  ResponseEntity.ok().build();
    }
    @GetMapping("/refresh/token")
    public void getRefreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        log.info(request.getHeader(AUTHORIZATION));
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                String refresh_token = authorizationHeader.substring("Bearer ".length());
                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                JWTVerifier verfier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verfier.verify(refresh_token);
                String username = decodedJWT.getSubject();
                User user=userService.getUser(username);
                String access_token= JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+10*60*1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles",user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                        .sign(algorithm);
        /*response.setHeader("access_token",access_token);
        response.setHeader("refresh_token",refresh_token);*/
                HashMap<String,String>token=new HashMap<>();
                token.put("access_token",access_token);
                token.put("refresh_token",refresh_token);
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(),token);

            } catch (Exception exception) {
                log.error("Error in :{}",exception.getMessage());
                response.setHeader("error", exception.getMessage());
                response.setStatus(FORBIDDEN.value());
                //response.sendError(FORBIDDEN.value());
                HashMap<String,String> error=new HashMap<>();
                response.setContentType(APPLICATION_JSON_VALUE);
                error.put("error_in_refresh_token_message",exception.getMessage());
                new ObjectMapper().writeValue(response.getOutputStream(),error);
            }
        }
        else{
          throw new RuntimeException("token is missing");

        }
    }
}
@Data
class RoleForm{
    private String username;
    private String role;
}
