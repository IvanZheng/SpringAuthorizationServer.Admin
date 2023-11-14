package springauthorizationserver.portal;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import springauthorizationserver.core.config.EnableJpaSpringAuthorizationServer;

@SpringBootApplication
@EnableJpaSpringAuthorizationServer
public class AuthorizationServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServerApplication.class, args);
    }


}
