package com.sentinelql.authentication.auth;

import com.sentinelql.authentication.config.JwtService;
import com.sentinelql.authentication.email.EmailService;
import com.sentinelql.authentication.user.*;
import jakarta.mail.MessagingException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private static final String CONFIRMATION_URL = "http://localhost:8081/api/v1/auth/confirm?token=%s";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final TokenRepository tokenRepository;
    private final EmailService emailService;

    @Transactional
    public String register(RegistrationRequest request) {
        // check if user exists
        boolean userExists = userRepository.findByEmail(request.getEmail()).isPresent();
        if (userExists) {
            throw new IllegalStateException("email already taken");
        }

        // transform request to user
        User user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(UserRole.USER)
                .build();

        // save user
        userRepository.save(user);

        // Generate token
        String generatedToken = UUID.randomUUID().toString();
        Token token = Token.builder()
                .token(generatedToken)
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMinutes(15))
                .user(user)
                .build();

        tokenRepository.save(token);

        // send confirmation email
        try {
            emailService.sendEmail(
                    user.getEmail(),
                    request.getFirstname(),
                    null,
                    String.format(CONFIRMATION_URL, generatedToken)
            );
        } catch (MessagingException e) {
            e.printStackTrace();
        }
        // return success or failure
        return generatedToken;
    }

    public String authenticate(AuthenticationRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );
        } catch (Exception e) {
            e.printStackTrace();
            throw new IllegalStateException(e.getMessage());
        }

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();

        String jwtToken = jwtService.generateToken(user);

        return jwtToken;
    }

    public String confirm(String token) {
        // check if token exists
        Token tokenFromDb = tokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalStateException("Token not found"));

        // check if token is expired
        if (tokenFromDb.getExpiresAt().isBefore(LocalDateTime.now())) { // LocalDateTime.now().isAfter(tokenFromDb.getExpiresAt())

            // generate new token and send to user
            String generatedToken = UUID.randomUUID().toString();
            Token newToken = Token.builder()
                    .token(generatedToken)
                    .createdAt(LocalDateTime.now())
                    .expiresAt(LocalDateTime.now().plusMinutes(15))
                    .user(tokenFromDb.getUser())
                    .build();

            tokenRepository.save(newToken);

            try {
                emailService.sendEmail(
                        tokenFromDb.getUser().getEmail(),
                        tokenFromDb.getUser().getFirstname(),
                        null,
                        String.format(CONFIRMATION_URL, generatedToken)
                );
            } catch (MessagingException e) {
                e.printStackTrace();
            }

            return "Token expired. A new token has been sent to your email";
        }

        // confirm user
        User user = userRepository.getById(tokenFromDb.getUser().getId());
        user.setEnabled(true);
        userRepository.save(user);

        tokenFromDb.setValidatedAt(LocalDateTime.now());
        tokenRepository.save(tokenFromDb);

        return "Your account successfully activated";
    }
}
