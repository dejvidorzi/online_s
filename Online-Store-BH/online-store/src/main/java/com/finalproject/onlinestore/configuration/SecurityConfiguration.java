package com.finalproject.onlinestore.configuration;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
@RequiredArgsConstructor
public class SecurityConfiguration {
    private UserDetailsService userDetailsService;

    private static final List<String> ORIGIN = Collections.singletonList("http://localhost:3000");
    private static final List<String> METHODS = Collections.singletonList("*");
    private static final List<String> HEADERS = Collections.singletonList("*");
    private static final long MAX_AGE = 3600L;
    
    public SecurityConfiguration(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    // Authorization
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
     // Configure CORS
        http.cors()
                .configurationSource(request -> getConfiguration())
                .and()
                .csrf((csrf)-> csrf.disable())
                .authorizeHttpRequests((authorize) -> authorize
                                // Configure request matchers for authorization
                                .requestMatchers("/api/auth/**").permitAll()
                                .requestMatchers(HttpMethod.GET, "/api/products/findAll").permitAll()
                                .requestMatchers(HttpMethod.POST, "api/categories").hasRole("ADMIN")
                                .requestMatchers(HttpMethod.POST, "api/products").hasRole("ADMIN")
                                .requestMatchers(HttpMethod.POST, "api/product/{productId}/reviews").hasRole("ADMIN")
                                .anyRequest().authenticated()
                )
                .httpBasic(Customizer.withDefaults());

        return http.build();
    }

    // Private method for CORS configuration


    // CORS configuration

    // PasswordEncoder bean configuration
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // DAO Authentication Manager
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }


    private CorsConfiguration getConfiguration() {
        CorsConfiguration cors = new CorsConfiguration();
        cors.setAllowedOrigins(ORIGIN);
        cors.setAllowedMethods(METHODS);
        cors.setAllowedHeaders(HEADERS);
        cors.setAllowCredentials(true);
        cors.setExposedHeaders(List.of("Authorization"));
        cors.setMaxAge(MAX_AGE);
        return cors;
    }
}
