package jwt.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);       // 서버가 응답할때 json을 자바스크립트에서 치라할 수 있게할지 설정
        config.addAllowedOrigin("*");   // 모든 ip 응답 허용
        config.addAllowedHeader("*");   // 모든 header 응답 허용
        config.addAllowedMethod("*");   // 모든 http 메서드 허용
        source.registerCorsConfiguration("/api/**", config);    // /api/ 로 시작되는 경로
        return new CorsFilter(source);
    }
}
