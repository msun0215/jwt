package com.example.jwt.config.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// Spring Security의 UsernamePasswordAuthenticationFilter 사용
// /login 요청해서 username, password를 POST로 전송하면
// UsernamePasswordAuthenticationFilter가 동작함

@RequiredArgsConstructor
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JWTAuthenticationFilter : 로그인 시도중");

        // 1. username, password를 받아서
        // 2. 정상인지 authenticationManager로 로그인 시도.
        // 3. PrincipalDetailsService가 호출됨 -> loadUserByUsername(String username)이 실행됨
        // 4. PrincipalDetails를 Session에 담고 ▶ 권한 관리를 위해서
        // 5. JWT Token을 만들어서 응답해주면 된다
        return super.attemptAuthentication(request, response);
    }
}
