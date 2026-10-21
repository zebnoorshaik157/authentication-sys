
package com.authsystem.security;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.authsystem.security.filter.JwtAuthenticationFilter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@Configuration
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final CustomOAuth2UserService customOAuth2UserService;

    public SecurityConfig(
            JwtAuthenticationFilter jwtAuthenticationFilter,
            OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler,
            CustomOAuth2UserService customOAuth2UserService) {

        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.oAuth2LoginSuccessHandler = oAuth2LoginSuccessHandler;
        this.customOAuth2UserService = customOAuth2UserService;
    }

    @Bean
    public OAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {

        DefaultOAuth2AuthorizationRequestResolver delegate =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository,
                        "/oauth2/authorization");

        return new OAuth2AuthorizationRequestResolver() {

            @Override
            public OAuth2AuthorizationRequest resolve(
                    HttpServletRequest request) {

                return customizeRequest(
                        request,
                        delegate.resolve(request));
            }

            @Override
            public OAuth2AuthorizationRequest resolve(
                    HttpServletRequest request,
                    String clientRegistrationId) {

                return customizeRequest(
                        request,
                        delegate.resolve(request, clientRegistrationId));
            }

            private OAuth2AuthorizationRequest customizeRequest(
                    HttpServletRequest request,
                    OAuth2AuthorizationRequest authorizationRequest) {

                if (authorizationRequest == null) {
                    return null;
                }

                String registrationId =
                        request.getRequestURI().substring(
                                request.getRequestURI().lastIndexOf('/') + 1);

                HttpSession session = request.getSession(false);

                if (session != null) {
                    Object pendingProvider =
                            session.getAttribute(
                                    "OAUTH_LINK_PENDING_PROVIDER");

                    Object pendingEmail =
                            session.getAttribute(
                                    "OAUTH_LINK_PENDING_EMAIL");

                    Object pendingTime =
                            session.getAttribute(
                                    "OAUTH_LINK_PENDING_TIME");

                    boolean recentIntent = pendingTime instanceof Long
                            && System.currentTimeMillis()
                                    - (Long) pendingTime <= 5 * 60 * 1000L;

                    if (pendingProvider instanceof String
                            && pendingEmail instanceof String
                            && recentIntent
                            && registrationId.equalsIgnoreCase(
                                    (String) pendingProvider)) {

                        // Bind the intended account to this OAuth state.
                        session.setAttribute(
                                "OAUTH_LINK_TARGET_EMAIL",
                                pendingEmail);

                        session.setAttribute(
                                "OAUTH_LINK_TARGET_STATE",
                                authorizationRequest.getState());

                        session.removeAttribute(
                                "OAUTH_LINK_PENDING_EMAIL");

                        session.removeAttribute(
                                "OAUTH_LINK_PENDING_PROVIDER");

                        session.removeAttribute(
                                "OAUTH_LINK_PENDING_TIME");
                    }
                }

                // Preserve the existing GitHub account-selection behavior.
                if ("github".equalsIgnoreCase(registrationId)) {
                    return OAuth2AuthorizationRequest
                            .from(authorizationRequest)
                            .additionalParameters(parameters ->
                                    parameters.put(
                                            "prompt",
                                            "select_account"))
                            .build();
                }

                return authorizationRequest;
            }
        };
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            OAuth2AuthorizationRequestResolver authorizationRequestResolver)
            throws Exception {

        http
            .cors(Customizer.withDefaults())

            .csrf(csrf -> csrf
                .csrfTokenRepository(
                        CookieCsrfTokenRepository.withHttpOnlyFalse())
                .csrfTokenRequestHandler(
                        new CsrfTokenRequestAttributeHandler())
                .ignoringRequestMatchers(
                        "/register",
                        "/login",
                        "/api/auth/forgot-password",
                        "/api/auth/verify-otp",
                        "/api/auth/reset-password")
            )

            .logout(AbstractHttpConfigurer::disable)

            .sessionManagement(session -> session
                    .sessionCreationPolicy(
                            SessionCreationPolicy.STATELESS))

            .exceptionHandling(ex -> ex
                    .authenticationEntryPoint(
                            new HttpStatusEntryPoint(
                                    HttpStatus.UNAUTHORIZED)))

            .authorizeHttpRequests(auth -> auth

                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                .requestMatchers(
                        HttpMethod.POST,
                        "/api/auth/oauth/link/**")
                    .authenticated()

                .requestMatchers(
                        "/",
                        "/oauth-link-test.html",
                        "/register",
                        "/login",
                        "/refresh",
                        "/logout",
                        "/csrf",
                        "/error",
                        "/oauth2/**",
                        "/login/oauth2/**",
                        "/api/auth/forgot-password",
                        "/api/auth/verify-otp",
                        "/api/auth/reset-password",
                        "/swagger-ui/**",
                        "/v3/api-docs/**",
                        "/swagger-ui.html")
                    .permitAll()

                .requestMatchers("/admin/**").hasRole("ADMIN")

                .anyRequest().authenticated()
            )

            .oauth2Login(oauth2 -> oauth2
                .authorizationEndpoint(endpoint -> endpoint
                        .authorizationRequestResolver(
                                authorizationRequestResolver))
                .userInfoEndpoint(userInfo -> userInfo
                        .userService(customOAuth2UserService))
                .successHandler(oAuth2LoginSuccessHandler)
            )

            .addFilterBefore(
                    jwtAuthenticationFilter,
                    UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOrigins(
                List.of(
                        "http://localhost:3000",
                        "http://localhost:5173"));

        configuration.setAllowedMethods(
                List.of(
                        "GET",
                        "POST",
                        "PUT",
                        "PATCH",
                        "DELETE",
                        "OPTIONS"));

        configuration.setAllowedHeaders(
                List.of(
                        "Authorization",
                        "Content-Type",
                        "X-XSRF-TOKEN"));

        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}
