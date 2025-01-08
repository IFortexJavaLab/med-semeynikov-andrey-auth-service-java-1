package com.ifortex.internship.auth_service.repository;

import com.ifortex.internship.auth_service.model.constant.ERole;
import com.ifortex.internship.auth_service.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}