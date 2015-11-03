package com.sloppycoder.webapp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.session.web.http.SessionRepositoryFilter;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.filter.RequestContextFilter;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import javax.servlet.Filter;
import java.security.Principal;
import java.util.Map;

@SpringBootApplication
@Controller
@ComponentScan
@EnableOAuth2Sso
public class MainAppApplication extends WebMvcConfigurerAdapter {

    @Value("${security.oauth2.client.ssoLogoutUrl}")
    String ssoLogoutUrl;

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/ssologout").setViewName("ssologout");
    }

    @RequestMapping(value = {"/dashboard"})
    public String showDashboard(Map<String, Object> model) throws Exception {
        model.put("sso_logout_url", ssoLogoutUrl);
        return "dashboard";
    }

    @RequestMapping("/user")
    @ResponseBody
    public Principal user(Principal user) {
        return user;
    }

    @RequestMapping("/")
    public String index() {
        return "redirect:dashboard";
    }

    @Bean
    @ConditionalOnMissingBean(RequestContextFilter.class)
    public RequestContextFilter requestContextFilter() {

        return new RequestContextFilter();
    }

    @Bean
    public FilterRegistrationBean requestContextFilterChainRegistration(
            @Qualifier("requestContextFilter") Filter securityFilter) {

        FilterRegistrationBean registration = new FilterRegistrationBean(securityFilter);
        registration.setName("requestContextFilter");

        // note : must previous order of oAuth2ClientContextFilter
        registration.setOrder(SessionRepositoryFilter.DEFAULT_ORDER + 1);

        return registration;
    }

    @Bean
    public FilterRegistrationBean sessionRepositoryFilterRegistration(
            SessionRepositoryFilter sessionRepositoryFilter) {

        FilterRegistrationBean registration = new FilterRegistrationBean(sessionRepositoryFilter);
        registration.setName("springSessionRepositoryFilter");

        // note : must following order of oAuth2ClientContextFilter
        registration.setOrder(Integer.MAX_VALUE - 1);

        return registration;
    }

    public static void main(String[] args) {
        SpringApplication.run(MainAppApplication.class, args);
    }

    @Configuration
    @Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
    protected static class ApplicationSecurity extends WebSecurityConfigurerAdapter {

        @Autowired
        private SecurityProperties security;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // @formatter:off
            http
            .authorizeRequests()
                .antMatchers("/", "/ssologout").permitAll()
                .anyRequest().fullyAuthenticated()
            .and()
                .formLogin()
                    .loginPage("/login").failureUrl("/login?error")
                .permitAll()
            .and()
                .logout().permitAll();
            // @formatter:on
        }

    }

}
