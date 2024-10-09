package jwt.auth.config;

import jwt.auth.filter.MyFilter1;
import jwt.auth.filter.MyFilter2;
import jwt.auth.filter.MyFilter3;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<MyFilter1> filterRegistrationBean1() {
        FilterRegistrationBean<MyFilter1> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new MyFilter1());

        registrationBean.addUrlPatterns("/*");
        registrationBean.setOrder(1);// 낮을수록 실행순위가 높음
        return registrationBean;
    }
    @Bean
    public FilterRegistrationBean<MyFilter2> filterRegistrationBean2() {
        FilterRegistrationBean<MyFilter2> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new MyFilter2());

        registrationBean.addUrlPatterns("/*");
        registrationBean.setOrder(0);// 낮을수록 실행순위가 높음
        return registrationBean;
    }
    @Bean
    public FilterRegistrationBean<MyFilter3> filterRegistrationBean3() {
        FilterRegistrationBean<MyFilter3> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new MyFilter3());

        registrationBean.addUrlPatterns("/*");
        registrationBean.setOrder(2);// 낮을수록 실행순위가 높음
        return registrationBean;
    }
}
