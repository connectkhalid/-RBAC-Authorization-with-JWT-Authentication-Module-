package com.example.security.dto.request;

import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RoleDTO {
    @NotEmpty(message = "Role name is required")
    private String roleName;

    @NotEmpty(message = "Permission list is required")
    private List<String> permissionNames;
}
