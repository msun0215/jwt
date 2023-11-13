package com.example.jwt.filter;

import jakarta.servlet.*;

import java.io.IOException;

public class Filter3 implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("Filter3");
        // 계속 프로세스가 진행되도록 Chain에 넘겨줌
        filterChain.doFilter(servletRequest,servletResponse);


        /*
        프로세스 종료 희망시
        PrintWrite out=response.getWriter();
        out.print("안녕");
         */
    }
}
