package jwt.auth.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jwt.auth.config.auth.PrincipalDetails;
import jwt.auth.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.security.Principal;
import java.util.Date;

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
        try {
//            BufferedReader br = request.getReader();
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                System.out.println(input);
//            }
//            System.out.println(request.getInputStream().toString());
            ObjectMapper objectMapper = new ObjectMapper();
            User user = objectMapper.readValue(request.getInputStream(), User.class);
            System.out.println(user.getUsername());
            System.out.println(user.getPassword());
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            //2. PrincipalDetailsService가 호출되고 loadByUsername 메서드가 실행된다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            //3. PrincipalDetails를 세션에 담고 (권한관리를 위해 세션에 담는다.)
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 성공! 이름:" + principalDetails.getUser().getUsername());       //로그인이 정상적으로 수행됐음을 의미


            return authentication;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    //attemptAuthentication() 수행 후 인증이 정상적으로 되었으면 successfulAuthentication() 실행
    //여기서 JWT토큰을 만들어서 요청한 사용자에게 JWT토큰을 Response해준다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("로그인 성공!! successfulAuthentication 실행된다");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject("sungsanghyunToken")       //제목
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000*10)))    //만료시간 = 현재시간 + 60000*10 (10분)
                .withClaim("id", principalDetails.getUser().getId())                //토큰에 담을 정보
                .withClaim("username",principalDetails.getUser().getUsername())     //토큰에 담을 정보
                .sign(Algorithm.HMAC512("AsdfwqFgkhowFDkxvj%#4okH"));               //시크릿값 (증명)

        response.addHeader("Authorization", "Bearer " + jwtToken);

        //super.successfulAuthentication(request, response, chain, authResult);
        
    }

}
