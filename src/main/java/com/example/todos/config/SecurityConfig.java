package com.example.todos.config;

import java.util.Arrays;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import lombok.RequiredArgsConstructor;
import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console; 

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final AuthenticationProvider authenticationProvider;
  private final JwtAuthenticationFilter jwtAuthFilter;
  private final CorsConfigurationSource configSource;

  @Bean
  public SecurityFilterChain getSecurityFilterChain(HttpSecurity http) throws Exception {

    http.cors(cors -> cors.configurationSource(configSource)).csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(authorizeRequests -> authorizeRequests
            .requestMatchers(new AntPathRequestMatcher("/api/v1/auth/**"),  toH2Console()).permitAll().anyRequest().authenticated())
        .sessionManagement(sessionManagement -> sessionManagement
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authenticationProvider(authenticationProvider)
        .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        //TODO: Need to remove this fix as it'll lead ClickJacking attack. Better change to different local DB(HSQL DB)
        // Fix: For H2 DB IFrame internal render Support 
        http.headers(header->header.frameOptions(frame->frame.disable()));

    return http.build();
  }

  
}
