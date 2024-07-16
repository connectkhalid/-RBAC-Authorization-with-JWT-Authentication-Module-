package com.example.security.controller;

import com.example.security.common.model.AuthenticationResponse;
import com.example.security.common.model.User;
import com.example.security.authentication.dto.AuthenticationDTO;
import com.example.security.common.security.JwtUtilsParseToken;
import com.example.security.dto.request.RoleAssignDTO;
import com.example.security.dto.request.RoleDTO;
import com.example.security.authentication.service.AuthenticationService;
import com.example.security.authentication.service.RoleService;
import com.example.security.authentication.service.UserPermissionService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class UserController {
    private Logger log = LoggerFactory.getLogger(UserController.class);

    private final AuthenticationService authenticationService;
    private final UserPermissionService userPermissionService;
    private final RoleService roleService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody User request) {
        return ResponseEntity.ok(authenticationService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody AuthenticationDTO authenticationDTO) {
        log.info("user {} attempt to login", authenticationDTO.getEmail());
        return ResponseEntity.ok(authenticationService.login(authenticationDTO));
    }

    @PostMapping("/role")
    public ResponseEntity<Object> CreateRole(@Valid @RequestBody RoleDTO roleDTO) {
        return ResponseEntity.ok(roleService.createRole(roleDTO));
    }

    @PutMapping("/user-role")
    public ResponseEntity<Object> updateUserPermission(@Valid @RequestBody RoleAssignDTO roleAssignDTO) {
        log.info("update permission of a user");
        return ResponseEntity.ok(userPermissionService.updatePermission(roleAssignDTO));
    }
}
