package com.ems.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class WebSecurityConfiguration {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Configures in-memory users with game character names.
     */
    @Bean
    public InMemoryUserDetailsManager userDetailsService(PasswordEncoder passwordEncoder) {
        // Manager User
        UserDetails manager = User.withUsername("mario")
                .password(passwordEncoder.encode("mario@123"))
                .roles("MANAGER")
                .build();

        // Standard User
        UserDetails user = User.withUsername("luigi")
                .password(passwordEncoder.encode("luigi@123"))
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(manager, user);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz -> authz
                        // ADD THIS: The correct way to permit static resources
                        .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()

                        // Your existing rules remain the same
                        .requestMatchers("/delete**").hasRole("MANAGER")
                        .anyRequest().authenticated()
                )
                .httpBasic(withDefaults())
                .formLogin(withDefaults())
                .exceptionHandling(exceptions -> exceptions
                        .accessDeniedPage("/WEB-INF/views/denied.jsp")
                )
                .logout(logout -> logout
                        .logoutUrl("/logoutMe")
                        .logoutSuccessUrl("/loggedout")
                        .permitAll()
                )
                .sessionManagement(session -> session
                        .maximumSessions(1)
                );

        return http.build();
    }
}