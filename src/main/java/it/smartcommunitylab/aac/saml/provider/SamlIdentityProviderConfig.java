/*
 * Copyright 2023 the original author or authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package it.smartcommunitylab.aac.saml.provider;

import com.fasterxml.jackson.annotation.JsonIgnore;
import it.smartcommunitylab.aac.SystemKeys;
import it.smartcommunitylab.aac.identity.base.AbstractIdentityProviderConfig;
import it.smartcommunitylab.aac.identity.model.ConfigurableIdentityProvider;
import it.smartcommunitylab.aac.identity.provider.IdentityProviderSettingsMap;
import java.io.IOException;
import java.io.StringReader;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import  java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.core.Saml2X509Credential.Saml2X509CredentialType;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

public class SamlIdentityProviderConfig extends AbstractIdentityProviderConfig<SamlIdentityProviderConfigMap> {

    private static final long serialVersionUID = SystemKeys.AAC_SAML_SERIAL_VERSION;
    public static final String RESOURCE_TYPE =
        SystemKeys.RESOURCE_PROVIDER + SystemKeys.ID_SEPARATOR + SamlIdentityProviderConfigMap.RESOURCE_TYPE;

    private transient RelyingPartyRegistration relyingPartyRegistration;
    private transient RelyingPartyRegistration metadataRelyingPartyRegistration;
    private transient SamlIdentityProviderStatusMap statusMap;
    private String baseUrl;

    public SamlIdentityProviderConfig(String provider, String realm) {
        this(SystemKeys.AUTHORITY_SAML, provider, realm);
    }

    public SamlIdentityProviderConfig(String authority, String provider, String realm) {
        super(authority, provider, realm, new IdentityProviderSettingsMap(), new SamlIdentityProviderConfigMap());
        this.relyingPartyRegistration = null;
        this.metadataRelyingPartyRegistration = null;
    }

    public SamlIdentityProviderConfig(
        ConfigurableIdentityProvider cp,
        IdentityProviderSettingsMap settingsMap,
        SamlIdentityProviderConfigMap configMap
    ) {
        super(cp, settingsMap, configMap);
    }

    /**
     * Private constructor for JPA and other serialization tools.
     *
     * We need to implement this to enable deserialization of resources via
     * reflection
     */

    @SuppressWarnings("unused")
    private SamlIdentityProviderConfig() {
        super();
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getRepositoryId() {
        // not configurable, always isolate saml providers
        return getProvider();
    }

    @JsonIgnore
    public RelyingPartyRegistration getRelyingPartyRegistration() {
        if (relyingPartyRegistration == null) {
            try {
                relyingPartyRegistration = toRelyingPartyRegistration();
            } catch (IOException | CertificateException e) {
                throw new RuntimeException("error building registration: " + e.getMessage());
            }
        }

        return relyingPartyRegistration;
    }

    @JsonIgnore
    public RelyingPartyRegistration getMetadataRelyingPartyRegistration() {
        if (metadataRelyingPartyRegistration == null) {
            try {
                metadataRelyingPartyRegistration = toMetadataRelyingPartyRegistration();
            } catch (IOException | CertificateException e) {
                throw new RuntimeException("error building registration: " + e.getMessage());
            }
        }

        return metadataRelyingPartyRegistration;
    }

    private RelyingPartyRegistration.Builder relyingPartyRegistrationBuilder() throws IOException, CertificateException {
        // set base parameters
        String entityId = getEntityId();
        String assertionConsumerServiceLocation = assertionConsumerUrlTemplate();

        // ap autoconfiguration
        String idpMetadataLocation = configMap.getIdpMetadataUrl();
        // ap manual configuration (only if not metadata)
        String assertingPartyEntityId = configMap.getIdpEntityId();
        String ssoLoginServiceLocation = configMap.getWebSsoUrl();
        String ssoLogoutServiceLocation = configMap.getWebLogoutUrl();
        boolean signAuthNRequest =
            (configMap.getSignAuthNRequest() != null ? configMap.getSignAuthNRequest().booleanValue() : true);
        String verificationCertificate = configMap.getVerificationCertificate();
        Saml2MessageBinding ssoServiceBinding = getServiceBinding(configMap.getSsoServiceBinding());

        // via builder
        // providerId is unique, use as registrationId
        String registrationId = getProvider();
        RelyingPartyRegistration.Builder builder = RelyingPartyRegistration.withRegistrationId(registrationId);

        if (StringUtils.hasText(idpMetadataLocation)) {
            // read metadata to autoconfigure
            builder = RelyingPartyRegistrations.fromMetadataLocation(idpMetadataLocation).registrationId(
                registrationId
            );
        } else {
            // set manually
            builder.assertingPartyDetails(party ->
                party
                    .entityId(assertingPartyEntityId)
                    .singleSignOnServiceLocation(ssoLoginServiceLocation)
                    .wantAuthnRequestsSigned(signAuthNRequest)
                    .singleSignOnServiceBinding(ssoServiceBinding)
            );

            if (StringUtils.hasText(verificationCertificate)) {
                Saml2X509Credential verificationCredentials = getVerificationCertificate(verificationCertificate);
                builder.assertingPartyDetails(party ->
                    party.verificationX509Credentials(c -> c.add(verificationCredentials))
                );
            }
        }

        // set fixed config params
        builder.entityId(entityId).assertionConsumerServiceLocation(assertionConsumerServiceLocation);

        return builder;
    }

    private RelyingPartyRegistration toRelyingPartyRegistration() throws IOException, CertificateException {
        RelyingPartyRegistration.Builder builder = relyingPartyRegistrationBuilder();
        builder = buildSigningCredentials(builder, true);
        return builder.build();
    }

    // TODO throws exception if configuration is invalid
    private RelyingPartyRegistration toMetadataRelyingPartyRegistration() throws IOException, CertificateException {
        RelyingPartyRegistration.Builder builder = relyingPartyRegistrationBuilder();
        builder = buildSigningCredentials(builder, false);
        return builder.build();
    }

    private RelyingPartyRegistration.Builder buildSigningCredentials(RelyingPartyRegistration.Builder builder, Boolean onlyActiveCredential) throws IOException, CertificateException {
        // read rp parameters from map
        // note: only RSA keys supported
        List<SigningCredential> signingCredentialList = new ArrayList<>();

        if (onlyActiveCredential) {
            if(StringUtils.hasText(configMap.getSigningKey()) && StringUtils.hasText(configMap.getSigningCertificate())){
                signingCredentialList.add(new SigningCredential("legacy-default", configMap.getSigningKey(), configMap.getSigningCertificate()));
            } else {
                String activeSigningCredentialId = configMap.getActiveSigningCredentialId();
                List<SigningCredential> allCredentials = configMap.getSigningCredentials();

                if (allCredentials != null && !allCredentials.isEmpty()) {
                    SigningCredential credential = allCredentials.stream()
                            .filter(c -> StringUtils.hasText(activeSigningCredentialId) && activeSigningCredentialId.equals(c.getCredentialId()))
                            .findFirst()
                            .orElse(allCredentials.get(0));

                    signingCredentialList.add(credential);
                }
            }
        }else{
            if (StringUtils.hasText(configMap.getSigningKey()) && StringUtils.hasText(configMap.getSigningCertificate())) {
                signingCredentialList.add(new SigningCredential("legacy-default", configMap.getSigningKey(), configMap.getSigningCertificate()));

                if (configMap.getSigningCredentials() != null) {
                    signingCredentialList.addAll(configMap.getSigningCredentials());
                }
            } else {
                signingCredentialList = (configMap.getSigningCredentials() != null)
                        ? configMap.getSigningCredentials()
                        : Collections.emptyList();
            }
        }

        for (SigningCredential signingCredential : signingCredentialList) {
            String signingKey = signingCredential.getSigningKey();
            String signingCertificate = signingCredential.getSigningCertificate();

            // check if sign credentials are provided
            if (StringUtils.hasText(signingKey) && StringUtils.hasText(signingCertificate)) {
                //            // cleanup pem
                //            signingCertificate = cleanupPem("CERTIFICATE", signingCertificate);

                Saml2X509Credential signingCredentials = getCredentials(
                        signingKey,
                        signingCertificate,
                        Saml2X509CredentialType.SIGNING,
                        Saml2X509CredentialType.DECRYPTION
                );
                // add for signature
                builder.signingX509Credentials(c -> c.add(signingCredentials));
            }
        }

        return builder;
    }

    public String metadataUrlTemplate() {
        return "{baseUrl}/auth/" + getAuthority() + "/metadata/{registrationId}";
    }

    public String getMetadataUrl() {
        if (baseUrl != null) {
            UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(metadataUrlTemplate());
            return builder.buildAndExpand(Map.of("baseUrl", baseUrl, "registrationId", getProvider())).toUriString();
        }
        return null;
    }

    public String assertionConsumerUrlTemplate() {
        return "{baseUrl}/auth/" + getAuthority() + "/sso/{registrationId}";
    }

    public String getAssertionConsumerUrl() {
        if (baseUrl != null) {
            UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(assertionConsumerUrlTemplate());
            return builder.buildAndExpand(Map.of("baseUrl", baseUrl, "registrationId", getProvider())).toUriString();
        }
        return null;
    }

    public String getEntityId() {
        // let config override, this breaks some standards but saml...
        return configMap.getEntityId() != null
            ? configMap.getEntityId()
            : (getMetadataUrl() != null ? getMetadataUrl() : getProvider());
    }

    // export additional properties not supported by stock model
    public Boolean getRelyingPartyRegistrationIsForceAuthn() {
        return configMap.getForceAuthn();
    }

    public Boolean getRelyingPartyRegistrationIsPassive() {
        return configMap.getIsPassive();
    }

    public String getRelyingPartyRegistrationNameIdFormat() {
        return configMap.getNameIDFormat();
    }

    public Boolean getRelyingPartyRegistrationNameIdAllowCreate() {
        return configMap.getNameIDAllowCreate();
    }

    public Set<String> getRelyingPartyRegistrationAuthnContextClassRefs() {
        return configMap.getAuthnContextClasses();
    }

    public String getRelyingPartyRegistrationAuthnContextComparison() {
        return configMap.getAuthnContextComparison();
    }

    public boolean requireEmailAddress() {
        return configMap.getRequireEmailAddress() != null ? configMap.getRequireEmailAddress().booleanValue() : false;
    }

    public String getSubAttributeName() {
        String subAttributeName = configMap.getSubAttributeName();
        return StringUtils.hasText(subAttributeName) ? subAttributeName : null;
    }

    public SamlIdentityProviderStatusMap getStatusMap() {
        if (statusMap == null) {
            statusMap = new SamlIdentityProviderStatusMap();
            statusMap.setMetadataUrl(getMetadataUrl());
            statusMap.setAssertionConsumerUrl(getAssertionConsumerUrl());
        }

        return statusMap;
    }

    //
    private Saml2X509Credential getVerificationCertificate(String certificate)
        throws CertificateException, IOException {
        return new Saml2X509Credential(parseX509Certificate(certificate), Saml2X509CredentialType.VERIFICATION);
    }

    private Saml2X509Credential getCredentials(String key, String certificate, Saml2X509CredentialType... keyUse)
        throws IOException, CertificateException {
        //        PrivateKey pk = RsaKeyConverters.pkcs8().convert(new ByteArrayInputStream(key.getBytes()));
        PrivateKey pk = parsePrivateKeyFallback(key);
        X509Certificate cert = parseX509Certificate(certificate);
        return new Saml2X509Credential(pk, cert, keyUse);
    }

    private PrivateKey parsePrivateKeyFallback(String key) throws IOException {
        // first try as rsa
        PrivateKey pk = null;
        try {
            pk = parsePrivateKey(fixPem(key, "RSA PRIVATE KEY"));
        } catch (IllegalArgumentException | IOException e) {
            // fallback as private
            pk = parsePrivateKey(fixPem(key, "PRIVATE KEY"));
        }

        return pk;
    }

    private PrivateKey parsePrivateKey(String key) throws IOException {
        StringReader sr = new StringReader(key);
        PEMParser pr = new PEMParser(sr);
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        Object pem = pr.readObject();
        sr.close();

        if (pem instanceof PEMKeyPair) {
            PrivateKeyInfo privateKeyInfo = ((PEMKeyPair) pem).getPrivateKeyInfo();
            return converter.getPrivateKey(privateKeyInfo);
        } else if (pem instanceof PrivateKeyInfo) {
            return converter.getPrivateKey((PrivateKeyInfo) pem);
        }

        throw new IllegalArgumentException("invalid private key");
    }

    //    private X509Certificate parseX509Certificate(String source) {
    //        try {
    //            final CertificateFactory factory = CertificateFactory.getInstance("X.509");
    //            return (X509Certificate) factory.generateCertificate(
    //                    new ByteArrayInputStream(source.getBytes(StandardCharsets.UTF_8)));
    //        } catch (Exception e) {
    //            throw new IllegalArgumentException(e);
    //        }
    //    }

    private X509Certificate parseX509Certificate(String source) throws IOException, CertificateException {
        String src = fixPem(source, "CERTIFICATE");
        StringReader sr = new StringReader(src);
        PEMParser pr = new PEMParser(sr);
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        Object pem = pr.readObject();
        sr.close();

        if (pem instanceof X509CertificateHolder) {
            return converter.getCertificate((X509CertificateHolder) pem);
        }

        throw new IllegalArgumentException("invalid certificate");
    }

    private Saml2MessageBinding getServiceBinding(String value) {
        Saml2MessageBinding ssoServiceBinding = Saml2MessageBinding.POST;
        if ("HTTP-Redirect".equals(value)) {
            ssoServiceBinding = Saml2MessageBinding.REDIRECT;
        }

        return ssoServiceBinding;
    }

    //    // TODO rewrite with proper parser
    //    private String cleanupPem(String kind, String value) {
    //        // build headers
    //        // we set a fixed length separator because spring rsaKeyConverter checks for
    //        // this specific amount of dashes..
    //        String sep = "-----";
    //        String header = "BEGIN " + kind;
    //        String footer = "END " + kind;
    //
    //        String[] lines = value.split("\\R");
    //        String[] keyLines = lines;
    //
    //        if (lines.length > 2) {
    //            // headers?
    //            String headerLine = lines[0];
    //            String footerLine = lines[lines.length - 1];
    //
    //            if (headerLine.contains(header)) {
    //                // extract key
    //                keyLines = new String[lines.length - 2];
    //                System.arraycopy(lines, 1, keyLines, 0, keyLines.length);
    //            }
    //        }
    //
    //        // cleanup and rebuild string
    //        StringBuilder sb = new StringBuilder();
    //        sb.append(sep).append(header).append(sep).append("\n");
    //        for (int c = 0; c < keyLines.length; c++) {
    //            sb.append(keyLines[c].trim()).append("\n");
    //        }
    //
    //        sb.append(sep).append(footer).append(sep);
    //        return sb.toString();
    //    }

    private String fixPem(String value, String kind) {
        String sep = "-----";
        String begin = "BEGIN " + kind;
        String end = "END " + kind;

        String header = sep + begin + sep;
        String footer = sep + end + sep;

        String[] lines = value.split("\\R");

        if (lines.length > 2) {
            // headers?
            String headerLine = lines[0];
            String footerLine = lines[lines.length - 1];

            if (headerLine.startsWith(sep) && footerLine.startsWith(sep)) {
                // return unchanged, don't mess with content
                return value;
            }
        }

        // rewrite
        StringBuilder sb = new StringBuilder();
        sb.append(header).append("\n");
        for (int c = 0; c < lines.length; c++) {
            sb.append(lines[c].trim()).append("\n");
        }
        sb.append(footer);
        return sb.toString();
    }
}
