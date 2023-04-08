package com.izhar.springjwt.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// filter by once every request
// we have the option of using Filter or OncePerRequestFilter
@Component
@RequiredArgsConstructor // create constructor for any final fields
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService; // this interface already in-built inside springframework

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        // pass the JWT token in the Authentication Header, which is part of our request
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // check on the header
        if (authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response);
            return;
        }
        // Extract the jwt token from header, which is the string after "Bearer "
        jwt = authHeader.substring(7);
        // Extract userEmail from the token
        userEmail = jwtService.extractUsername(jwt);
        // check if user email given, and if it is already authenticated
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
        }
    }
}
