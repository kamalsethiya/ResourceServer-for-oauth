package com.appsdeveloperblog.ws.api.ResourceServer.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

//@EnableGlobalMethodSecurity(securedEnabled=true, prePostEnabled=true)
//@EnableWebSecurity
@Configuration
public class WebSecurity extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {

//		//below is with role and scope
		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());

		http// .cors().and()
				.authorizeRequests().antMatchers(HttpMethod.GET, "/users/status/check")
				// .hasAuthority("SCOPE_profile")
					.hasRole("developer")
				// .hasAnyAuthority("ROLE_developer")
				// .hasAnyRole("devleoper","user")
				.antMatchers(HttpMethod.GET, "/users/status/check/unprotected")
					.permitAll()
				.anyRequest()
					.authenticated()
				.and().oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwtAuthenticationConverter);

		// below is without role and scope
//		http//.cors().and()
//		.authorizeRequests()
//			.anyRequest().authenticated()
//			.and()
//		.oauth2ResourceServer()
//		.jwt();
	}

//	@Bean
//	CorsConfigurationSource corsConfigurationSource() {
//		CorsConfiguration corsConfiguration = new CorsConfiguration();
//		corsConfiguration.setAllowedOrigins(Arrays.asList("*"));
//		corsConfiguration.setAllowedMethods(Arrays.asList("GET", "POST"));
//		corsConfiguration.setAllowedHeaders(Arrays.asList("*"));
//
//		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//		source.registerCorsConfiguration("/**", corsConfiguration);
//
//		return source;
//	}
//	
}
