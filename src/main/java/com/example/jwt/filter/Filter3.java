package com.example.jwt.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;

public class Filter3 implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest req= (HttpServletRequest) servletRequest;
        HttpServletResponse res= (HttpServletResponse) servletResponse;

        // req.setCharacterEncoding("UTF-8");  // HttpServletRequest는 한글 지원이 되지 않음

        // Token : cors <- 이걸 만들어줘야 함.
        // ID, PW가 정상적으로 들어와서 로그인이 완료되면 Token을 만들어주고 그거에 대한 Response를 해준다.
        // Request할때마다 header에 Authorization에 value 값으로 Token을 받음
        // 그 때 Token이 넘어오면 이 Token이 내가 만든 Token이 맞는지만 검증하면 된다.(RSA, HS256 방식)
        if(req.getMethod().equals("POST")){
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);

            if(headerAuth.equals("cors")){      // Token의 Authorization이 'cors'라는 이름으로 넘어온다면
                filterChain.doFilter(req, res);
            }else{
                PrintWriter outPrintWriter=res.getWriter();
                outPrintWriter.println("인증 안됨");
            }
        }

        System.out.println("Filter3");
        // 계속 프로세스가 진행되도록 Chain에 넘겨줌
        //filterChain.doFilter(servletRequest,servletResponse);


        /*
        프로세스 종료 희망시
        PrintWrite out=response.getWriter();
        out.print("안녕");
         */
    }
}
