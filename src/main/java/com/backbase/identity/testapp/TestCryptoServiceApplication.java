package com.backbase.identity.testapp;

import com.backbase.identity.fido2testharness.jackson.FidoTestLibraryModule;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import java.security.KeyPair;
import java.security.Security;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@EnableWebMvc
@SpringBootApplication
public class TestCryptoServiceApplication extends SpringBootServletInitializer {

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        SpringApplication.run(TestCryptoServiceApplication.class, args);
    }

    @Bean
    public Map<String, KeyPair> fido2KeyPairs() {
        return new HashMap<>();
    }

    @Bean
    public Module fidoTestLibraryModule() {
        return new FidoTestLibraryModule();
    }

    @Bean
    @Primary
    public ObjectMapper objectMapper(Module fidoTestLibraryModule) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(fidoTestLibraryModule);
        return mapper;
    }
}

@Configuration
class JacksonWebMvcConfig implements WebMvcConfigurer {
    private final ObjectMapper objectMapper;

    public JacksonWebMvcConfig(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void extendMessageConverters(List<HttpMessageConverter<?>> converters) {
        for (HttpMessageConverter<?> converter : converters) {
            if (converter instanceof MappingJackson2HttpMessageConverter) {
                ((MappingJackson2HttpMessageConverter) converter).setObjectMapper(objectMapper);
            }
        }
    }
}
