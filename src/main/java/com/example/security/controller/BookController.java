package com.example.security.controller;

import com.example.security.authorization.model.RequiresPermission;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/book")
public class BookController {

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> testMethod() {
        return ResponseEntity.ok("this method can be accessed by admin");
    }

    @GetMapping
    @RequiresPermission(permission = "book_read")
    public ResponseEntity<?> getUser() {
        return ResponseEntity.ok("book read permission");
    }

    @PutMapping
    @RequiresPermission(permission = "book_update")
    public ResponseEntity<?> updateUser() {
        return ResponseEntity.ok("book update permission");
    }

    @DeleteMapping("/{id}")
    @RequiresPermission(permission = "book_delete")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        return ResponseEntity.ok("book delete permission");
    }

    @DeleteMapping
    @RequiresPermission(permission = "book_delete")
    public ResponseEntity<?> deleteUser() {
        return ResponseEntity.ok("book delete permission");
    }
}
