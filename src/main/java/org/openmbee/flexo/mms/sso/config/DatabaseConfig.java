package org.openmbee.flexo.mms.sso.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import javax.sql.DataSource;
import java.util.Properties;

@Configuration
@EnableJpaRepositories(basePackages = "org.openmbee.flexo.mms.sso.repository")
@EnableTransactionManagement
public class DatabaseConfig {

    @Value("${spring.datasource.url:jdbc:sqlite:sso-database.db}")
    private String databaseUrl;
    
    @Value("${spring.datasource.username:#{null}}")
    private String username;
    
    @Value("${spring.datasource.password:#{null}}")
    private String password;

    @Bean
    public DataSource dataSource() {
        DataSourceBuilder<?> dataSourceBuilder = DataSourceBuilder.create();
        
        // Determine driver based on URL
        if (databaseUrl.startsWith("jdbc:postgresql")) {
            dataSourceBuilder.driverClassName("org.postgresql.Driver");
        } else if (databaseUrl.startsWith("jdbc:sqlite")) {
            dataSourceBuilder.driverClassName("org.sqlite.JDBC");
        } else {
            throw new IllegalArgumentException("Unsupported database URL: " + databaseUrl);
        }
        
        dataSourceBuilder.url(databaseUrl);
        
        // Set username and password if provided
        if (username != null && !username.isEmpty()) {
            dataSourceBuilder.username(username);
        }
        
        if (password != null && !password.isEmpty()) {
            dataSourceBuilder.password(password);
        }
        
        return dataSourceBuilder.build();
    }

    @Bean
    public LocalContainerEntityManagerFactoryBean entityManagerFactory() {
        LocalContainerEntityManagerFactoryBean em = new LocalContainerEntityManagerFactoryBean();
        em.setDataSource(dataSource());
        em.setPackagesToScan("org.openmbee.flexo.mms.sso.entity");

        HibernateJpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
        vendorAdapter.setGenerateDdl(true);
        em.setJpaVendorAdapter(vendorAdapter);

        Properties properties = new Properties();
        
        // Determine dialect based on URL
        if (databaseUrl.startsWith("jdbc:postgresql")) {
            properties.setProperty("hibernate.dialect", "org.hibernate.dialect.PostgreSQLDialect");
        } else if (databaseUrl.startsWith("jdbc:sqlite")) {
            properties.setProperty("hibernate.dialect", "org.hibernate.community.dialect.SQLiteDialect");
        }
        
        properties.setProperty("hibernate.hbm2ddl.auto", "update");
        properties.setProperty("hibernate.show_sql", "true");
        em.setJpaProperties(properties);

        return em;
    }

    @Bean
    public PlatformTransactionManager transactionManager() {
        JpaTransactionManager transactionManager = new JpaTransactionManager();
        transactionManager.setEntityManagerFactory(entityManagerFactory().getObject());
        return transactionManager;
    }
}