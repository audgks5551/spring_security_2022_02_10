package com.example.springsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .anyRequest().authenticated();

        http
                .formLogin()
                //.loginPage("/loginPage") // 로그인 페이지 주소 (이걸 활성화하면 기본으로 제공하는 템플릿 사용불가)
                .defaultSuccessUrl("/") // 로그인 성공시 리다이렉트하는 주소
                .failureUrl("/login") // 로그인 실패시 리다이렉트하는 주소
                .loginProcessingUrl("/login") // 로그인 form action 정의
                .usernameParameter("userId") // 로그인 form 안에 아이디 input태그의 name 정의
                .passwordParameter("passwd") // 로그인 form 안에 비밀번호 input태그의 name 정의

                // 로그인 성공 시 작동하는 객체 정의
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("Authentication : " + authentication.getName());
                        response.sendRedirect("/");
                    }
                })

                // 로그인 실패 시 작동하는 객체 정의
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("Exception : " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })

                .permitAll() // 로그인 주소에 들어와야 인증이 가능하므로 모든 사용자 접근 허용
                ;

    }


}
