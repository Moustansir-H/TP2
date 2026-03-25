package com.example.auth.service;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth.security")
public class AuthSecurityProperties {

    private String serverMasterKey = "change-me-in-production";
    private long timestampWindowSeconds = 60;
    private long nonceTtlSeconds = 120;
    private long tokenTtlSeconds = 900;

    public String getServerMasterKey() {
        return serverMasterKey;
    }

    public void setServerMasterKey(String serverMasterKey) {
        this.serverMasterKey = serverMasterKey;
    }

    public long getTimestampWindowSeconds() {
        return timestampWindowSeconds;
    }

    public void setTimestampWindowSeconds(long timestampWindowSeconds) {
        this.timestampWindowSeconds = timestampWindowSeconds;
    }

    public long getNonceTtlSeconds() {
        return nonceTtlSeconds;
    }

    public void setNonceTtlSeconds(long nonceTtlSeconds) {
        this.nonceTtlSeconds = nonceTtlSeconds;
    }

    public long getTokenTtlSeconds() {
        return tokenTtlSeconds;
    }

    public void setTokenTtlSeconds(long tokenTtlSeconds) {
        this.tokenTtlSeconds = tokenTtlSeconds;
    }
}

