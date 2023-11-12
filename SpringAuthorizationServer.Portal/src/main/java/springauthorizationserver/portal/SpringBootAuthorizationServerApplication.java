package springauthorizationserver.portal;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = {"springauthorizationserver.core"})
public class SpringBootAuthorizationServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringBootAuthorizationServerApplication.class, args);
    }


}
