package com.sanctuary.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        
        // Permite solicitudes desde tu origen de React
        config.addAllowedOrigin("http://localhost:4000");
        
        // Permite métodos HTTP comunes
        config.addAllowedMethod("GET");
        config.addAllowedMethod("POST");
        config.addAllowedMethod("PUT");
        config.addAllowedMethod("DELETE");
        config.addAllowedMethod("OPTIONS");
        
        // Permite todos los encabezados
        config.addAllowedHeader("*");
        
        // Permite cookies (si las necesitas)
        config.setAllowCredentials(true);
        
        
        source.registerCorsConfiguration("/api/**", config);
        return new CorsFilter(source);
    }
}