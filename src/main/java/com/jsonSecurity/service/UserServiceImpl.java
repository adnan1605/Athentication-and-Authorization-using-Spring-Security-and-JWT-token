package com.jsonSecurity.service;

import com.jsonSecurity.model.Role;
import com.jsonSecurity.model.User;
import com.jsonSecurity.repo.RoleRepo;
import com.jsonSecurity.repo.UserRepo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

    @Autowired
    UserRepo userRepo;

    @Autowired
    RoleRepo roleRepo;
    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepo.findByUsername(username);
        if (user == null) {
            log.error("user not found in data base");
            throw new UsernameNotFoundException("user not found in data base");
        } else {
            log.info("user found in data base : {}", username);
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role ->
                authorities.add(new SimpleGrantedAuthority(role.getName()))
        );
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
    }

    @Override
    public User saveUser(User user) {
        // log.info("saving user");
        //log.info("{}");
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        log.info("saving new User {} in database", user.getUsername());
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("saving new Role {} in databases", role.getName());
        return roleRepo.save(role);
    }

    @Override
    public void addRoleToUser(String userName, String roleName) {
        User user = userRepo.findByUsername(userName);

        Role role = roleRepo.findByName(roleName);
        // log.info("adding role {} to user");
        user.getRoles().add(role);
    }

    @Override
    public User getUser(String userName) {
        log.info("fetching user {}", userName);
        return userRepo.findByUsername(userName);
    }

    @Override
    public List<User> getUsers() {
        return userRepo.findAll();
    }


}
