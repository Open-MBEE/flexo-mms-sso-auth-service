package org.openmbee.flexo.mms.sso;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.openmbee.flexo.mms.sso.oauth.OAuthServerProperties;

@SpringBootApplication
@EnableConfigurationProperties(OAuthServerProperties.class)
public class SsoMicroserviceApplication {

    public static void main(String[] args) {
        SpringApplication.run(SsoMicroserviceApplication.class, args);
    }
}
