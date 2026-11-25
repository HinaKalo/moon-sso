package cloud.moonl.sso.example;

import cloud.moonl.sso.spring.web.MoonSsoSecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The application's own security rules; {@link MoonSsoSecurity#apply} adds Moon SSO login
 * (PKCE, iss check, silent refresh), HTMX-aware redirects and logout. The webhook and
 * back-channel logout endpoints are served by the starter in front of this chain.
 */
@Configuration(proxyBeanMethods = false)
class SecurityConfig {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http, MoonSsoSecurity moonSso) {
		http.authorizeHttpRequests((requests) -> requests.requestMatchers("/", "/error", "/favicon.ico", "/css/**")
			.permitAll()
			.anyRequest()
			.authenticated());
		moonSso.apply(http);
		return http.build();
	}

}
