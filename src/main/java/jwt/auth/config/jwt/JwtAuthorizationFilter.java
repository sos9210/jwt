package jwt.auth.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Verification;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jwt.auth.config.auth.PrincipalDetails;
import jwt.auth.model.User;
import jwt.auth.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;

/**
    시큐리티가 filter가지고 있는데 그 필터중에 BasicAuthenticationFilter 라는 것이 있는데
    권한이나 인증이 필요한 특정주소를 요청하면 위 필터를 반드시 거치게 된다.
    만약에 권한이 인증이 필요한 주소가 아니라면 위 필터를 거치지 않는다.
  */

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private final UserRepository userRepository;
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    // 인증이나 권한이 필요한 주소요청이 있을때 해당 필터를 실행함.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        //super.doFilterInternal(request, response, chain);
        System.out.println("인증이나 권한이 필요한 주소 요청됨.");

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader: " + jwtHeader);

        /**jwt 토큰을 검증해서 정상적인 사용자인지 확인한다.**/
        //header가 있는지 확인한다.
        if(jwtHeader == null || !jwtHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }
        String jwtToken = jwtHeader.replace("Bearer ","");
        System.out.println("jwtToken: " + jwtToken);

        String username = JWT.require(Algorithm.HMAC512("AsdfwqFgkhowFDkxvj%#4okH")).build()
                .verify(jwtToken)
                .getClaim("username").asString();

        System.out.println("signUsername : " + username);

        //서명이 정상적으로 됨
        if(username != null) {
            User user = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(user);

            // JWT토큰 서명을 통해서 서명이 정상적으면 Authentication 객체를 만들어준다.
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    principalDetails,
                    null,
                    principalDetails.getAuthorities()
            );

            //강제로 시큐리티 세션에 접근하여 Authentication 객체 저장.
            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        }
    }
}
