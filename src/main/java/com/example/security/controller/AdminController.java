package com.example.security.controller;

import com.example.security.authorization.model.RequiresPermission;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/admin")
public class AdminController {

    @PostMapping
    @RequiresPermission(permission = "admin_create")
    public ResponseEntity<?> createMethod() {
        return ResponseEntity.ok("admin_create access");
    }

    @PutMapping
    @RequiresPermission(permission = "admin_update")
    public ResponseEntity<?> updateMethod() {
        return ResponseEntity.ok("admin_update access");
    }

    @DeleteMapping
    @RequiresPermission(permission = "admin_delete")
    public ResponseEntity<?> deleteMethod() {
        return ResponseEntity.ok("admin_delete access");
    }
}
