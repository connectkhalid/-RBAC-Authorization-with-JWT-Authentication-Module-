package com.example.security.authentication.repositories;

import com.example.security.common.model.Permission;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PermissionRepository extends JpaRepository<Permission, Long> {
    List<Permission> findByPermissionNameIn(List<String> permissionNames);

    Optional<Permission> findByPermissionName(String permissionNames);
}
