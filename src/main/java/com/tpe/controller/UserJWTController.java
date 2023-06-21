package com.tpe.controller;

import com.tpe.dto.LoginRequest;
import com.tpe.dto.RegisterRequest;
import com.tpe.security.JWTUtils;
import com.tpe.security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
public class UserJWTController {

    @Autowired
    private UserService userService;

    @Autowired
    private JWTUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    //user register
    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@Valid @RequestBody RegisterRequest registerRequest){

        userService.saveUser(registerRequest);

        return new ResponseEntity<>("user is registered successfully", HttpStatus.CREATED); //201
    }

    //user login --> username,password -- response:TOKEN

    @PostMapping("/login") //post kullanimi standart haline gelmis
    public ResponseEntity<String> login(@Valid @RequestBody LoginRequest loginRequest){
         Authentication authentication = authenticationManager  //username,password valide eder aksi halde exception
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUserName(),loginRequest.getPassword()));

        String token = jwtUtils.generateToken(authentication);

        return new ResponseEntity<>(token,HttpStatus.CREATED);
    }

    @GetMapping("/goodbye")
    @PreAuthorize("hasRole('STUDENT')")
    public ResponseEntity<String> goodbye(){
        return ResponseEntity.ok("GoodBye Security:)");
    }


}
