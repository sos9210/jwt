package jwt.auth.config.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

//formLogin을 disable했기때문에 기존 loginProccess는 동작하지않아서 이 방법을 사용
//스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음
// /login 요청해서 username,password 전송하면 UsernamePasswordAuthenticationFilter 동작함

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인시도를 위해서 실행되는 메서드
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter.attemptAuthentication");

        //1. username,password를 검증해서 로그인시도를 하면
        //2. PrincipalDetailsService가 호출되고 loadByUsername 메서드가 실행된다.
        //3. PrincipalDetails를 세션에 담고 (권한관리를 위해 세션에 담는다.)
        //4. JWT토큰을 만들어서 응답한다.
        return super.attemptAuthentication(request, response);
    }
}
