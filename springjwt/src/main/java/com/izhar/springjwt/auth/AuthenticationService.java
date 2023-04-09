package com.izhar.springjwt.auth;

import com.izhar.springjwt.config.JwtService;
import com.izhar.springjwt.user.Role;
import com.izhar.springjwt.user.User;
import com.izhar.springjwt.user.UserRepository;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.apache.el.parser.Token;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;

import java.net.http.HttpHeaders;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        // build user object
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        var savedUser = repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveUser(savedUser,jwtToken);
        return AuthenticationResponse
                .builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }


    public AuthenticationResponse authenticate(AuthenticationRequest request) {

        // check username and password and see if valid. else, will throw an exception
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        // since username and password is authenticated, then...
        System.out.println("I'm here");
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow(); // TODO: to further handle this exception in the future
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        // got additional code here 13:46
        return AuthenticationResponse
                .builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();

    }

    public void refreshToken(
            HttpServlet request,
            HttpServletResponse response
    ) {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
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
    }
}
