package jwt.auth.config;

import jwt.auth.config.jwt.JwtAuthenticationFilter;
import jwt.auth.filter.MyFilter1;
import jwt.auth.filter.MyFilter3;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final CorsFilter corsFilter;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        AuthenticationManager authenticationManager =  http.getSharedObject(AuthenticationManager.class);

        //servlet filter를 security filter에 등록하는 방법
        //servlet filter보다 security filter가 먼저 동작을한다.
        //따라서 servlet filter가 먼저 동작하게하려면 아래 방법을 사용하자
        //http.addFilterBefore(먼저 동작시킬 필터인스턴스, 어떤클래스보다 먼저실행할것인지 클래스정보);
        http.addFilterBefore(new MyFilter3(),BasicAuthenticationFilter.class);

        http.csrf(AbstractHttpConfigurer::disable);
        // JWT로그인 방식으로 할때 사용하는 설정 SessionCreationPolicy.STATELESS : http session을 생성하지않음
        return http.sessionManagement(config -> config.sessionCreationPolicy(SessionCreationPolicy.STATELESS) )
                .addFilter(corsFilter) // @CrossOrigin은 인증이 필요하지않은 경우에 사용, 인증이 있을때는 시큐리티 필터에 등록
                .addFilter(new JwtAuthenticationFilter(authenticationManager))   //AuthentcationManager를 전달해야함
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable) //
                .authorizeHttpRequests(authorize -> {
                    authorize.requestMatchers("/api/v1/user/**").hasAnyRole("USER", "ADMIN","MANAGER")
                            .requestMatchers("/api/v1/manager/**").hasAnyRole("MANAGER", "ADMIN")
                            .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                            .anyRequest().permitAll();
                })
                .build();
    }
}
