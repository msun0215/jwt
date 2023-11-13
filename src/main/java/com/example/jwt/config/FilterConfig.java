package com.example.jwt.config;

import com.example.jwt.filter.Filter1;
import com.example.jwt.filter.Filter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


// SecurityConfig에 따로 addFilter할 필요 없이 별도로 Configuration을 작성해줘도 된다.
@Configuration
public class FilterConfig {
    @Bean
    public FilterRegistrationBean<Filter1> filter1(){
        FilterRegistrationBean<Filter1> bean=new FilterRegistrationBean<>(new Filter1());
        bean.addUrlPatterns("/*");
        bean.setOrder(1);   // 낮은 번호가 Filter 중에서 가장 먼저 실행됨.
        return bean;
    }


    @Bean
    public FilterRegistrationBean<Filter2> filter2(){
        FilterRegistrationBean<Filter2> bean=new FilterRegistrationBean<>(new Filter2());
        bean.addUrlPatterns("/*");
        bean.setOrder(0);   // 낮은 번호가 Filter 중에서 가장 먼저 실행됨.
        return bean;
    }
}
