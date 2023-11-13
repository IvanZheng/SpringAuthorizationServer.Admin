package springauthorizationserver.portal;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication(scanBasePackages = {"springauthorizationserver.portal", "springauthorizationserver.core.service"})
@EnableJpaRepositories(basePackages = "springauthorizationserver.core.repository")
@EntityScan(basePackages = {"springauthorizationserver.core.entity"})
public class AuthorizationServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServerApplication.class, args);
    }


}
