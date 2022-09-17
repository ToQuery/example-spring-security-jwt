package io.github.toquery.example.spring.security.jwt;

import io.github.toquery.example.spring.security.jwt.properties.OAuthAuthorizationProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(value = {OAuthAuthorizationProperties.class})
public class ExampleSpringSecurityJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(ExampleSpringSecurityJwtApplication.class, args);
	}

}
