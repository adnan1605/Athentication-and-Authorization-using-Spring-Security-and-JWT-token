package com.jsonSecurity.service;

import com.jsonSecurity.model.Role;
import com.jsonSecurity.model.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);

    Role saveRole(Role role);

    void addRoleToUser(String userName, String roleName);

    User getUser(String userName);

    List<User> getUsers();
}
