package com.example.jwt.config.auth;

import com.example.jwt.model.User;
import com.example.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// Spring Security Default Route
// http://localhost:8080/login -> formLogin().disable()을 했기 때문에 동작안함.
// -> Filter를 만들어줘서 작동하게 해야 함!

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService의 loadUserByusername() : "  +username);
        User userEntity=userRepository.findByUsername(username);
        System.out.println("Entity : "+userEntity);
        // session.setAttribute("loginUser", user);
        return new PrincipalDetails(userEntity);
    }
}
