package com.jsonSecurity;

import com.jsonSecurity.model.Role;
import com.jsonSecurity.model.User;
import com.jsonSecurity.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class JsonProjectApplication {

    public static void main(String[] args) {
        SpringApplication.run(JsonProjectApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder() {

        return new BCryptPasswordEncoder();
    }

   @Bean
   CommandLineRunner run(UserService userService) {
        return args -> {
            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_MANAGER"));
            userService.saveRole(new Role(null, "ROLE_DEVELOPER"));
            userService.saveRole(new Role(null, "ROLE_TESTER"));


            userService.saveUser(new User(null, "Adnan Khan", "adnan_1605", "1234", new ArrayList<>()));
            userService.saveUser(new User(null, "Irfan", "irfan", "1234", new ArrayList<>()));
            userService.saveUser(new User(null, "Sumit", "sumit", "1234", new ArrayList<>()));
            userService.saveUser(new User(null, "Kshitiz", "kshitiz", "1234", new ArrayList<>()));

            userService.addRoleToUser("adnan_1605","ROLE_USER");
            userService.addRoleToUser("irfan","ROLE_USER");
            userService.addRoleToUser("sumit","ROLE_USER");
            userService.addRoleToUser("kshitiz","ROLE_USER");
            userService.addRoleToUser("adnan_1605","ROLE_USER");

        };

    }

}
