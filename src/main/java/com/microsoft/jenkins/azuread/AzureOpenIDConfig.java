package com.microsoft.jenkins.azuread;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.net.URL;

@JsonIgnoreProperties(ignoreUnknown = true)
public class AzureOpenIDConfig {

    private final String issuer;
    private final URL jwksUri;

    @JsonCreator(mode = JsonCreator.Mode.PROPERTIES)
    public AzureOpenIDConfig(@JsonProperty("issuer") String issuer, @JsonProperty("jwks_uri") URL jwksUri) {
        this.issuer = issuer;
        this.jwksUri = jwksUri;
    }

    @JsonGetter
    public String getIssuer() {
        return issuer;
    }

    @JsonGetter
    public URL getJwksUri() {
        return jwksUri;
    }
}
