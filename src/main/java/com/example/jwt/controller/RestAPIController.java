package com.example.jwt.controller;

import com.example.jwt.model.User;
import com.example.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1")
@RequiredArgsConstructor
public class RestAPIController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("home")    // index route
    public String home(){
        return "<h1>home</h1>";
    }

    @PostMapping("/token")  // token check route
    public String token(){
        return "<h1>token</h1>";
    }

    @PostMapping("/join")   // 회원가입 route
    public String join(@RequestBody User user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword())); // 암호화
        user.setRoles("ROLE_USER");     // 기본 설정 ROLE
        userRepository.save(user);
        return "회원가입 완료";
    }
}
