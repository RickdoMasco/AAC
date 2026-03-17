package it.smartcommunitylab.aac.spid.provider;

import java.io.Serializable;

public class SigningCredential implements Serializable {
    private String credentialId;
    private String signingKey;
    private String signingCertificate;

    public SigningCredential() { }

    public SigningCredential(String credentialId, String signingKey, String signingCertificate){
        this.credentialId = credentialId;
        this.signingKey = signingKey;
        this.signingCertificate = signingCertificate;
    }

    public String getCredentialId() {
        return this.credentialId;
    }

    public void setCredentialId(String credentialId){
        this.credentialId = credentialId;
    }

    public String getSigningKey() {
        return this.signingKey;
    }

    public void setSigningKey(String signingKey){
        this.signingKey = signingKey;
    }

    public String getSigningCertificate() {
        return this.signingCertificate;
    }

    public void setSigningCertificate(String signingCertificate){
        this.signingCertificate = signingCertificate;
    }
}
