package com.example.security.authorization.services;

import com.example.security.common.model.Permission;
import com.example.security.common.model.Role;
import com.example.security.common.model.User;
import com.example.security.common.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RbacService {
    @Autowired
    private UserRepository userRepository;

    /**
     * Checks if the currently authenticated user has the specified permission.
     *
     * This method retrieves the currently authenticated user's details from the
     * SecurityContext, fetches the user's roles and permissions from the repository,
     * and checks if the specified permission is among the user's permissions.
     *
     * @param permission The permission to check for (case-insensitive).
     * @return {@code true} if the user has the specified permission, {@code false} otherwise.
     */
    public boolean hasPermission(String permission) {
        String username = (String) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        User user = userRepository.findByEmail(username).orElse(null);

        if (user == null) {
            return false;
        }

        List<Role> roles = user.getRoles();
        for (Role role : roles) {
            List<Permission> permissions = role.getPermissions();
            for (Permission permission1 : permissions) {
                if (permission.equalsIgnoreCase(permission1.getPermissionName())) {
                    return true;
                }
            }
        }
        return false;
    }
}
