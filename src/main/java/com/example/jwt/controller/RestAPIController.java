package com.example.jwt.controller;

import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.model.User;
import com.example.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

//@RestController
//@RequestMapping("/api/v1")
//@RequiredArgsConstructor
//// @CrossOrigin  // CORS 허용
//public class RestAPIController {
//
//    private final UserRepository userRepository;
//    private final BCryptPasswordEncoder bCryptPasswordEncoder;
//
//    // 모든 사람이 접근 가능함
//    @GetMapping("home")    // index route
//    public String home(){
//        return "home";
//    }
//
//
//    // TIP : JWT를 사용하면 UserDetailsService를 호출하지 않기 때문에 @AuthenticationPrincipal 사용 불가능
//    // 왜냐하면 @AuthenticationPrincipal은 UserDetailsService에서 return 될 때 만들어지기 때문
//
//
//    // User or Manager or Admin able to access
//    @GetMapping("/user")
//    public String user(Authentication authentication){
//        PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
//        System.out.println("principal : "+principal.getUser().getId());
//        System.out.println("principal : "+principal.getUser().getUsername());
//        System.out.println("principal : "+principal.getUser().getPassword());
//
//        return "<h1>user</h1>";
//    }
//
//    // Manager or Admin able to access
//    @GetMapping("/manager/reports")
//    public String reports(){
//        return "<h1>reports</h1>";
//    }
//
//    // Admin able to access
//    @GetMapping("/admin")
//    public List<User> admin(){
//        return userRepository.findAll();
//    }
//
//
//    @PostMapping("/join")   // 회원가입 route
//    public String join(@RequestBody User user){
//        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword())); // 암호화
//        user.setRoles("ROLE_USER");     // 기본 설정 ROLE
//        userRepository.save(user);
//        return "회원가입 완료";
//    }
//}

@RestController
@RequiredArgsConstructor
public class RestAPIController{
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    @GetMapping("home")
    public String home(){return "<h1>home</h1>";}

    @PostMapping("token")
    public String token(){return "<h1>token</h1>";}

    @PostMapping("join")
    public String join(@RequestBody User user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        //user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입 완료";
    }
}
