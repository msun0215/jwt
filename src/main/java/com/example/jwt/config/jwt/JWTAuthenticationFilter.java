package com.example.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

/*
     Spring Security의 UsernamePasswordAuthenticationFilter 사용
     /login 요청해서 username, password를 POST로 전송하면
     UsernamePasswordAuthenticationFilter가 동작함
     but, formLogin().disable() 설정을 하면서 이 Filter가 동작을 하지 않음
     따라서 이 Filter를 SecurityConfig에 다시 등록을 해주어야 한다.
*/
@RequiredArgsConstructor
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;  // 로그인을 실행하기 위한 역할

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JWTAuthenticationFilter : 로그인 시도중");

        // 1. username, password를 받아서
        try {
            /* //가장 원초적인 방법
            BufferedReader br=request.getReader();
            String input=null;
            while((input=br.readLine())!=null)  System.out.println(input);
            System.out.println(request.getInputStream().toString());
            */

            //=> request가 x-www-form-urlencoded 방식으로 넘어오면 &를 사용해서 parsing하면 되지만
            //다른 방식으로 넘어오면 parsing하는 방식이 바뀌기 때문에 사용하지 않음

            System.out.println(request.getInputStream().toString());
            ObjectMapper om=new ObjectMapper();
            User user=om.readValue(request.getInputStream(), User.class);
            System.out.println(user);


            System.out.println("P"+user.getPassword());
            // Token 생성
            UsernamePasswordAuthenticationToken authenticationToken
                    =new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행된다.
            // 함수 실행 이후 정상이면 authentication이 return됨.
            // DB에 있는 username과 password가 일치한다.
            System.out.println(authenticationToken);
            Authentication authentication=authenticationManager.authenticate(authenticationToken);  // login 정보

            // Principal 객체로 받아와서 getUser가 출력이 된다는 것은 로그인에 성공했다는 뜻임.
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println(principalDetails.getUser().getUsername());   // 로그인이 정상적으로 되었다는 뜻
            // authentication 객체가 session 영역에 저장을 해야하고 그 방법이 return 해주면 됨
            // return 이유는 권한관리를 security가 대신 해주기 때문에 편하려고 하는 것.
            // 굳이 JWT Token을 사용하면서 Session을 만들 필요는 없으나, 권한 처리를 위해서 JWT Token을 사용함

            System.out.println("1");
            // authentication 객체가 session 영역에 저장이 된다.
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        // 2. 정상인지 authenticationManager로 로그인 시도.
        // 3. PrincipalDetailsService가 호출됨 -> loadUserByUsername(String username)이 실행됨
        // 4. PrincipalDetails를 Session에 담고 ▶ 권한 관리를 위해서
        // 5. JWT Token을 만들어서 응답해주면 된다

        System.out.println("2");
        return null;    // error 발생시 null return
    }

    // attemptAuthentication 실행 이후 인증이 정상적으로 되었다면
    // successfulAuthentication에서 JWT Token을 생성해서
    // request 요청한 user에게 JWT Token을 response 하면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        PrincipalDetails principalDetails=(PrincipalDetails)authResult.getPrincipal();
        System.out.println("Authentication이 실행됨 : 인증이 완료되었다는 뜻임");

        // RSA방식이 아닌, Hash암호방식
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())    // token 별명 느낌?
                        .withExpiresAt(new Date(System.currentTimeMillis()+JWTProperties.EXPIRATION_TIME))  // Token 만료 시간 -> 현재시간 + 만료시간
                                .withClaim("id", principalDetails.getUser().getId())    // 비공개 Claim -> 넣고싶은거 아무거나 넣으면 됨
                                        .withClaim("username", principalDetails.getUser().getUsername())    // 비공개 Claim
                                                .sign(Algorithm.HMAC512(JWTProperties.SECRET));  // HMAC512는 SECRET KEY를 필요로 함
        response.addHeader(JWTProperties.HEADER_STRING, "Bearer "+jwtToken);
    }


    /*
    <Spring Security>
    username, password 로그인 정상
    Server쪽 SessionID 생성 -> client Cookie SessionID 를 응답
    request를 보낼때마다 Cookie SessionID를 항상 들고 Server로 request하기 때문에
    Server는 SessionID가 유효한지 판단해서, 유효하면 인증이 필요한 페이지로 접근하게 하면 된다.

    <JWT>
    username, password 로그인 정상
    JWT Token을 생성하여 client 쪽으로 응답
    request할 때마다 JWT Token을 가지고 요청한다.
    Server는 JWT Token이 유효한지를 판단한다.(Filter를 만들어야 함)
     */
}
