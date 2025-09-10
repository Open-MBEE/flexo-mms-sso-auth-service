package org.openmbee.flexo.mms.sso.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.ApplicationRunner;

@Configuration
public class LoggingConfig {
    private static final Logger logger = LoggerFactory.getLogger(LoggingConfig.class);

    @Bean
    public ApplicationRunner loggerRunner() {
        return args -> {
            logger.debug("Debug logging is active");
            logger.info("Logback configuration is active");
            logger.info("Application started with arguments: {}", (Object) args.getSourceArgs());
        };
    }
}