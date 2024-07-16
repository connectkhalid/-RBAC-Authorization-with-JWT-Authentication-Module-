package com.example.security.authentication.service;

import com.example.security.common.exception.CustomException;
import com.example.security.common.model.Permission;
import com.example.security.common.model.Role;
import com.example.security.dto.request.RoleDTO;
import com.example.security.authentication.repositories.PermissionRepository;
import com.example.security.authentication.repositories.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class RoleService {
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    public String createRole(RoleDTO roleDTO) {
        if (!roleRepository.findByRoleName(roleDTO.getRoleName()).isEmpty()) {
            throw new CustomException("Role already exists", HttpStatus.BAD_REQUEST);
        }
        List<Permission> permissions = permissionRepository.findByPermissionNameIn(roleDTO.getPermissionNames());

        if (permissions.size() != roleDTO.getPermissionNames().size()) {
            throw new CustomException("Permission not exists", HttpStatus.BAD_REQUEST);
        }
        Role role = Role
                .builder()
                .roleName(roleDTO.getRoleName())
                .permissions(permissions)
                .build();
        roleRepository.save(role);
        return "role saved successfully";
    }
}
