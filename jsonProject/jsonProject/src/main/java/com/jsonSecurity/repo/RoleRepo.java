package com.jsonSecurity.repo;

import com.jsonSecurity.model.Role;
import com.jsonSecurity.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepo extends JpaRepository<Role,Long> {
    Role findByName(String name);
}
