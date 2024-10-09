package jwt.auth.filter;


import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("필터3");

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        // 토큰 : ASDF
        // 토큰은 id,pwd등이 정상적으로 검증되고 로그인이 완료되면 토큰을 생성하고 응답해준다.
        // 클라이언트는 요청할때마다 header에 Authorization에 value값으로 토큰을 서버에 보낸다.
        // 클라이언트에서 서버로 토큰이 넘어오면 이 토큰이 서버에서 만든 토큰이 맞는지 검증한다.( RSA, HS256 )
        if(request.getMethod().equals("POST")) {
            System.out.println("POST 요청 !");
            String headerAuth = response.getHeader("Authorization");
            System.out.println("headerAuth : " + headerAuth);

            if(headerAuth.equals("ASDF")) {
                filterChain.doFilter(request, response);
            } else {
                PrintWriter writer = res.getWriter();
                writer.println("인증안됨");
            }
        }
    }
}
