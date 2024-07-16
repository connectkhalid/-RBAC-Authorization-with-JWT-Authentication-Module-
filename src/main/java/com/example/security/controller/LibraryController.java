package com.example.security.controller;

import com.example.security.authorization.model.RequiresPermission;
import com.example.security.common.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/library")
public class LibraryController {
    private final UserRepository userRepository;

    @PostMapping
    @RequiresPermission(permission = "library_create")
    public ResponseEntity<?> createLibrary() {
        return ResponseEntity.ok("create_library permission");
    }

    @GetMapping
    @RequiresPermission(permission = "library_search")
    public ResponseEntity<?> getLibrary() {
        return ResponseEntity.ok("search_library permission");
    }

    @PutMapping
    @RequiresPermission(permission = "library_update")
    public ResponseEntity<?> updateLibrary() {
        return ResponseEntity.ok("update_library permission");
    }

    @DeleteMapping
    @RequiresPermission(permission = "library_delete")
    public ResponseEntity<?> deleteLibrary() {
        return ResponseEntity.ok("delete_library permission");
    }

    /*@GetMapping("/{id}")
    @PreAuthorize("hasRole('GUEST_USER')")
    @PostAuthorize("returnObject.body.email == authentication.name")
    public ResponseEntity<UserDTO> getUser(@PathVariable Long id) {
        User user = userRepository.findById(id).orElseThrow(() -> new CustomException("user not found", HttpStatus.NOT_FOUND));
        return ResponseEntity.ok(UserDTO.builder()
                .email(user.getEmail())
                .build());
    }*/
}
