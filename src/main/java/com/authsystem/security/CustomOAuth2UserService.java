
package com.authsystem.security;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

@Service
public class CustomOAuth2UserService
        implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final DefaultOAuth2UserService delegate =
            new DefaultOAuth2UserService();

    private final RestClient restClient = RestClient.create();

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest)
            throws OAuth2AuthenticationException {

        OAuth2User oauthUser = delegate.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration()
                .getRegistrationId();

        Map<String, Object> attributes =
                new HashMap<>(oauthUser.getAttributes());

        if ("github".equals(registrationId)) {
            String email = (String) attributes.get("email");

            if (email == null || email.isBlank()) {
                email = fetchVerifiedGitHubEmail(userRequest);
            }

            if (email == null || email.isBlank()) {
                throw new OAuth2AuthenticationException(
                        new OAuth2Error("missing_verified_email"),
                        "GitHub did not provide a verified email address");
            }

            attributes.put("email", email);
            attributes.put("email_verified", true);

            String name = (String) attributes.get("name");
            if (name == null || name.isBlank()) {
                attributes.put("name", attributes.get("login"));
            }
        }

        String nameAttributeKey = userRequest.getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName();

        return new DefaultOAuth2User(
                oauthUser.getAuthorities(),
                attributes,
                nameAttributeKey);
    }

    private String fetchVerifiedGitHubEmail(
            OAuth2UserRequest userRequest) {

        List<Map<String, Object>> emails = restClient.get()
                .uri("https://api.github.com/user/emails")
                .header(
                        HttpHeaders.AUTHORIZATION,
                        "Bearer " + userRequest.getAccessToken().getTokenValue())
                .header(
                        HttpHeaders.ACCEPT,
                        "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .body(
                        new org.springframework.core.ParameterizedTypeReference<
                                List<Map<String, Object>>>() {});

        if (emails == null) {
            return null;
        }

        // Prefer the primary email, but only if verified.
        for (Map<String, Object> item : emails) {
            if (Boolean.TRUE.equals(item.get("primary"))
                    && Boolean.TRUE.equals(item.get("verified"))) {
                return (String) item.get("email");
            }
        }

        // Otherwise use another verified email.
        for (Map<String, Object> item : emails) {
            if (Boolean.TRUE.equals(item.get("verified"))) {
                return (String) item.get("email");
            }
        }

        return null;
    }
}
