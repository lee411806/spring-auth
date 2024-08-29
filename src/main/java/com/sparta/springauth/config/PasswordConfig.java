package com.sparta.springauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordConfig { //passwordConfig

    @Bean
    public PasswordEncoder passwordEncoder() { //passwordEncoder
        return new BCryptPasswordEncoder(); // PasswordEncoder 구현체
        // BCrypt : 해쉬함수  -> 강력한 hash매커니즘 중 하나 , 이걸 사용해서 패스워드 인코딩
    }
}