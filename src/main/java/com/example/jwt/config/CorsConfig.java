package com.example.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.web.filter.CorsFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class CorsConfig {
    @Bean
    public CorsFilter corsFilter(){
        UrlBasedCorsConfigurationSource source=new UrlBasedCorsConfigurationSource();
        CorsConfiguration config=new CorsConfiguration();
        config.setAllowCredentials(true);   // 내 서버가 응답할 때 json을 javascript에서 처리할 수 있게 할지를 설정
        config.addAllowedOrigin("*");   // 모든 ip에 응답을 허용함
        config.addAllowedHeader("*");   // 모든 header에 응답을 허용함
        config.addAllowedMethod("*");   // 모든 post, get, put, delete, patch 등의 Method 요청을 허용함
        source.registerCorsConfiguration("/api/**", config);    // /api/**로 들어오는 url에 대해서는 config대로 정의함
        return new CorsFilter(source);

    }
}
