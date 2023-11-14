package springauthorizationserver.core.config;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import springauthorizationserver.core.service.JpaOAuth2AuthorizationConsentService;
import springauthorizationserver.core.service.JpaOAuth2AuthorizationService;
import springauthorizationserver.core.service.JpaRegisteredClientRepository;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
@Import({JpaOAuth2AuthorizationConsentService.class, JpaOAuth2AuthorizationService.class, JpaRegisteredClientRepository.class})
@EnableJpaRepositories(basePackages = "springauthorizationserver.core.repository")
@EntityScan(basePackages = {"springauthorizationserver.core.entity"})
public @interface EnableJpaSpringAuthorizationServer {
}
