package com.example.auth.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AuthSecurityPropertiesTest {

    @Test
    void testDefaultValues() {
        AuthSecurityProperties props = new AuthSecurityProperties();

        assertEquals("change-me-in-production", props.getServerMasterKey());
        assertEquals(60, props.getTimestampWindowSeconds());
        assertEquals(120, props.getNonceTtlSeconds());
        assertEquals(900, props.getTokenTtlSeconds());
    }

    @Test
    void testSettersAndGetters() {
        AuthSecurityProperties props = new AuthSecurityProperties();

        props.setServerMasterKey("new-key");
        props.setTimestampWindowSeconds(120);
        props.setNonceTtlSeconds(240);
        props.setTokenTtlSeconds(1800);

        assertEquals("new-key", props.getServerMasterKey());
        assertEquals(120, props.getTimestampWindowSeconds());
        assertEquals(240, props.getNonceTtlSeconds());
        assertEquals(1800, props.getTokenTtlSeconds());
    }
}

