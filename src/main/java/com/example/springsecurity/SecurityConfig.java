package com.example.springsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

//@Configuration
//@EnableWebSecurity
class SecurityConfig100 extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS", "USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN", "SYS", "USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

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

                        // 세션 캐쉬를 이용하여 인가 거부를 당한 url로 이동
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                        String redirectUrl = savedRequest.getRedirectUrl();
                        response.sendRedirect(redirectUrl);

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

        http
                .logout()
                .logoutUrl("/logout") // 로그아웃 주소
                .logoutSuccessUrl("/login") // 로그아웃 성공 시 리다이렉트할 주소

                // 로그아웃할 때 실행하는 함수
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate(); // 세션 무효화
                    }
                })

                // 로그아웃이 성공적으로 마쳤을 때 실행하는 함수
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me") // 쿠키 삭제
                ;

        http
                .rememberMe() // 세션이 없어도 자동 로그인 가능
                .rememberMeParameter("remember-me") // input 태그의 name 정의
                .tokenValiditySeconds(3600) // remember-me 쿠키가 살아있는 시간
                .userDetailsService(userDetailsService) // 서비스 함수
                ;

        http
                .sessionManagement() // 세션 관리

                // 동시 세션 제어(세션이 초과했을 때 어떻게 대응할지 정함)

                .maximumSessions(1) // 최대 세션 개수 정의

                // 세션이 초과하였을 때의 설정 { true: "세션이 더이상 추가되지않게함(로그인 안됨)", false: "이전 사용자 제거" }
                // 세션은 브라우저를 기준
                .maxSessionsPreventsLogin(false)
        ;

        http
                .sessionManagement()

                // 세션 고정 보호(해커가 세션을 주입한 경우)
                .sessionFixation().changeSessionId() // 기본값 (옵션: none, migrateSession, newSession)
        ;

        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                                                    // SessionCreationPolicy. Always 		:  스프링 시큐리티가 항상 세션 생성
                                                    // SessionCreationPolicy. If_Required 	:  스프링 시큐리티가 필요 시 생성(기본값)
                                                    // SessionCreationPolicy. Never   		:  스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
                                                    // SessionCreationPolicy. Stateless	 	:  스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음
        ;

        http
                .antMatcher("/**") // 특정 경로 지정(지금은 모든 범위 설정)
                .authorizeRequests() // 요청에 대한 권한을 지정

                .antMatchers("/login").permitAll() // 로그인 페이지 모든 사용자 허용

                .antMatchers("/user").hasRole("USER") // "/user" 경로는 USER 권한을 가진 유저만 접근가능

                // **주의 사항** - 설정 시 구체적인 경로가 먼저 오고 그것 보다 큰 범위의 경로가 뒤에 오도록 해야 한다
                .antMatchers("/admin/pay").hasRole("ADMIN") // "/admin/pay" 경로는 ADMIN과 SYS 권한을 가진 유저만 접근가능
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')") // "/admin/**" 경로는 ADMIN과 SYS 권한을 가진 유저만 접근가능

                .anyRequest().authenticated() // 어떤 요청이던지 인증된 사용자의 접근을 허용
        ;

        http
                .exceptionHandling()

                // 인증 예외 처리 함수
//                .authenticationEntryPoint(new AuthenticationEntryPoint() {
//                    @Override
//                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                })

                // 인가 예외 처리 함수 (http 403)
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                })
        ;

        http
                .csrf() // 기본 활성화되어 있음
                        //.disabled() : 비활성화
        ;
    }
}

@Configuration
@EnableWebSecurity
@Order(0)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .antMatcher("/admin/**")
                .authorizeRequests()
                .anyRequest().authenticated()
        .and()
                .httpBasic()
        ;

    }
}

@Configuration
@Order(1)
class SecurityConfig2 extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .anyRequest().permitAll()
        .and()
                .formLogin()
        ;
    }
}
