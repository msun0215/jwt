package com.example.jwt.filter;

import jakarta.servlet.*;

import java.io.IOException;

public class filter1 implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("Filter1");
        filterChain.
    }
}
