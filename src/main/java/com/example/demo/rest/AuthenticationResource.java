package com.example.demo.rest;


import com.example.demo.config.JwtUtils;
import com.example.demo.domain.dto.AuthenticationRequest;
import com.example.demo.repository.UserRepository;
import io.jsonwebtoken.JwtBuilder;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationResource {

    private final UserRepository userRepository;
    private  final AuthenticationManager authenticationManager ;
    private final JwtUtils jwtUtils;

    @PostMapping("/authenticate")
    public ResponseEntity<String> authenticate(
          @RequestBody AuthenticationRequest request
    ){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail() , request.getPassword())
        );

        final UserDetails user = userRepository.findUserByEmail(request.getEmail());
        if(user != null){
             return  ResponseEntity.ok(jwtUtils.generateToken(user));
        }

        return ResponseEntity.status(400).body("some error has occurred");
    }

    @GetMapping("/hello")
    public  String Hello(){
        return "hello anas ";
    }


}
