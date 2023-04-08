package com.izhar.springjwt.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
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

        // check if user email given, and if it is already authenticated or not
        // if not authenticated then...
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            // we get the user details from the database
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            // then we check if the user is valid or not here
            if(jwtService.isTokenValid(jwt, userDetails)){
                // if username and token is valid, then we create the obj of type UsernamePasswordAuthenticationToken
                // this is required by spring to update our security context i.e. userDetailsService
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        // we pass in the token obj the user details, credentials and authority as parameters
                        userDetails,
                        null, // we don't have credentials when we create a user, so passing it as null
                        userDetails.getAuthorities()
                );
                // we then extend the token with the details of the request
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                // finally we update the authentication token here
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
