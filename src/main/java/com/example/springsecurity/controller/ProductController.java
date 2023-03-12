package com.example.springsecurity.controller;

import com.example.springsecurity.config.JwtService;
import com.example.springsecurity.config.UserDet;
import com.example.springsecurity.model.Response;
import com.example.springsecurity.model.Roles;
import com.example.springsecurity.model.User;
import com.example.springsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/v1")
public class ProductController {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/createUser")
    public ResponseEntity<?> createUser(@RequestBody User user){
        if(userRepository.findByEmail(user.getEmail()) != null){
            throw new RuntimeException("User not found");
        }
user.setRoles(Roles.ROLE_USER);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return  ResponseEntity.ok(userRepository.save(user));
    }
    @PostMapping("/createAdmin")
    public ResponseEntity<?> createAdmin(@RequestBody User user){
        if(userRepository.findByEmail(user.getEmail()) != null){
            throw new RuntimeException("User not found");
        }
        user.setRoles(Roles.ROLE_ADMIN);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return  ResponseEntity.ok(userRepository.save(user));
    }

    @GetMapping("/product")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public ResponseEntity<List<?>> getProduct(){
        return  ResponseEntity.ok(new ArrayList<>(List.of("Kenny","First")));
    }

    @PostMapping("/product")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<?>> createProduct(@RequestBody String product){
        return  ResponseEntity.ok(new ArrayList<>(List.of("Kenny","First",product)));
    }
    @PostMapping("/login")
    public ResponseEntity<Response> login(@RequestBody User user){
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                user.getEmail(),user.getPassword()
        ));
        if(!authentication.isAuthenticated()){
            throw new RuntimeException("Invalid credentials");
        }
        Object principal = authentication.getPrincipal();
        UserDet user1 = (UserDet) principal;

        return ResponseEntity.ok().header(HttpHeaders.AUTHORIZATION, jwtService.generateToken(user1))
                .body(new Response(jwtService.generateToken(user1)));
    }
}
