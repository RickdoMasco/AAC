/*
 * Copyright 2024 the original author or authors
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

package it.smartcommunitylab.aac.spid.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.xml.namespace.NamespaceContext;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpMethod;
import org.springframework.web.client.RestTemplate;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.fasterxml.jackson.annotation.JsonIgnore;

import it.smartcommunitylab.aac.SystemKeys;
import it.smartcommunitylab.aac.crypto.CertificateParser;
import it.smartcommunitylab.aac.identity.base.AbstractIdentityProviderConfig;
import it.smartcommunitylab.aac.identity.model.ConfigurableIdentityProvider;
import it.smartcommunitylab.aac.identity.provider.IdentityProviderSettingsMap;
import it.smartcommunitylab.aac.spid.SpidIdentityAuthority;
import it.smartcommunitylab.aac.spid.model.SpidAttribute;
import it.smartcommunitylab.aac.spid.model.SpidAttributeConsumingService;
import it.smartcommunitylab.aac.spid.model.SpidMetadataConfiguration;
import it.smartcommunitylab.aac.spid.model.SpidRegistration;
import it.smartcommunitylab.aac.spid.model.SpidUserAttribute;

public class SpidIdentityProviderConfig extends AbstractIdentityProviderConfig<SpidIdentityProviderConfigMap> {

    public static final long serialVersionUID = SystemKeys.AAC_SPID_SERIAL_VERSION;
    public static final String RESOURCE_TYPE =
        SystemKeys.RESOURCE_PROVIDER + SystemKeys.ID_SEPARATOR + SpidIdentityProviderConfigMap.RESOURCE_TYPE;

    private static final String XPATH_EXPRESSION_ENTITY_ID = "/md:EntityDescriptor/@entityID";
    private static final String XPATH_EXPRESSION_ORGANIZATION_NAME = "/md:EntityDescriptor/md:Organization/md:OrganizationName/text()";
    private static final String XPATH_EXPRESSION_ORGANIZATION_DISPLAY_NAME = "/md:EntityDescriptor/md:Organization/md:OrganizationDisplayName/text()";
    private static final String XPATH_EXPRESSION_ORGANIZATION_URL = "/md:EntityDescriptor/md:Organization/md:OrganizationURL/text()";
    private static final String XPATH_EXPRESSION_CONTACT_PERSON_EMAIL_ADDRESS = "/md:EntityDescriptor/md:ContactPerson/md:EmailAddress/text()";
    private static final String XPATH_EXPRESSION_CONTACT_PERSON_IPA_CODE = "/md:EntityDescriptor/md:ContactPerson/md:Extensions/spid:IPACode/text()";
    private static final String XPATH_EXPRESSION_ATTRIBUTE_CONSUMING_SERVICES = "/md:EntityDescriptor//md:AttributeConsumingService";
    private static final String XPATH_EXPRESSION_ACS_SERVICE_NAME = "md:ServiceName/text()";
    private static final String XPATH_EXPRESSION_ACS_REQUESTED_ATTRIBUTE = "md:RequestedAttribute";
    private static final String XPATH_EXPRESSION_SIGNING_CERTIFICATES = "/md:EntityDescriptor//md:KeyDescriptor[@use='signing']//ds:X509Certificate";

    private static final int DEFAULT_TIMEOUT = 10000;
    private static final int DEFAULT_ATTRIBUTE_CONSUMING_SERVICE_INDEX = 0;
    private static final String DEFAULT_ATTRIBUTE_CONSUMING_SERVICE_NAME = "default";

    private transient Set<RelyingPartyRegistration> relyingPartyRegistrations;
    private transient Set<RelyingPartyRegistration> metadataRelyingPartyRegistrations;

    private Set<SpidRegistration> identityProviders;
    private SpidMetadataConfiguration metadataConfiguration;

    private transient SpidIdentityProviderStatusMap statusMap;
    private String baseUrl;

    private transient RestTemplate restTemplate;

    public SpidIdentityProviderConfig(String provider, String realm) {
        super(
            SystemKeys.AUTHORITY_SPID,
            provider,
            realm,
            new IdentityProviderSettingsMap(),
            new SpidIdentityProviderConfigMap()
        );
        this.relyingPartyRegistrations = null;
        this.metadataRelyingPartyRegistrations = null;
        this.identityProviders = Collections.emptySet();
        this.metadataConfiguration = null;
        this.restTemplate = null;
    }

    public SpidIdentityProviderConfig(
        ConfigurableIdentityProvider cp,
        IdentityProviderSettingsMap settings,
        SpidIdentityProviderConfigMap configs
    ) {
        super(cp, settings, configs);
        validateSigningCredentials();
        loadMetadataConfiguration();
    }

    /**
     * Private constructor for JPA and other serialization tools.
     *
     * We need to implement this to enable deserialization of resources via
     * reflection
     */
    @SuppressWarnings("unused")
    private SpidIdentityProviderConfig() {
        super();
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public SpidIdentityProviderStatusMap getStatusMap() {
        if (statusMap == null) {
            statusMap = new SpidIdentityProviderStatusMap();
            statusMap.setMetadataUrl(getMetadataUrl());
            statusMap.setAssertionConsumerUrl(getAssertionConsumerUrl());
            statusMap.setMetadataConfiguration(getMetadataConfiguration());
        }
        return statusMap;
    }

    public String metadataUrlTemplate() {
        return "{baseUrl}" + SpidIdentityAuthority.AUTHORITY_URL + "metadata/{registrationId}";
    }

    public String getMetadataUrl() {
        if (baseUrl != null) {
            UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(metadataUrlTemplate());
            return builder.buildAndExpand(Map.of("baseUrl", baseUrl, "registrationId", getMetadataRegistrationId())).toUriString();
        }
        return null;
    }

    public String assertionConsumerUrlTemplate() {
        return "{baseUrl}" + SpidIdentityAuthority.AUTHORITY_URL + "sso/{registrationId}";
    }

    public String getAssertionConsumerUrl(){
        if (baseUrl != null) {
            UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(assertionConsumerUrlTemplate());
            return builder.buildAndExpand(Map.of("baseUrl", baseUrl, "registrationId", getMetadataRegistrationId())).toUriString();
        }
        return null;
    }

    public Map<String, String> getMetadataConfiguration() {
        Map<String, String> config = new LinkedHashMap<>();
        config.put("entityId", getEntityId());
        config.put("organizationName", getOrganizationName());
        config.put("organizationDisplayName", getOrganizationDisplayName());
        config.put("organizationUrl", getOrganizationUrl());
        config.put("contactPersonEmailAddress", getContactPersonEmailAddress());
        config.put("contactPersonIpaCode", getContactPersonIPACode());

        getAttributeConsumingServices()
            .stream()
            .filter(acs -> acs.getIndex() == getAttributeConsumingServiceIndex())
            .findFirst()
            .ifPresent(acs -> config.put(
                "attributeConsumingServiceIndex " + acs.getIndex(),
                acs.getAttributes()
                    .stream()
                    .map(SpidAttribute::toString)
                    .sorted()
                    .collect(Collectors.joining(", "))
            ));

        return config;
    }

    /*
     * Extract a provider from a registration with pattern either {providerId}
     * or {providerId}|{idpKey} where idpKey is the key of the upstream
     * SPID identity provider.
     */
    public static String getProviderId(String decodedRegistrationId) {
        Assert.hasText(decodedRegistrationId, "registrationId can not be blank");

        // registrationId is {providerId}|{idpKey}
        String[] kp = StringUtils.split(decodedRegistrationId, "|");
        if (kp == null) {
            return decodedRegistrationId;
        }
        //kp[0], kp[1] = providerId, idpKey
        return kp[0];
    }

    public Set<SpidRegistration> getIdentityProviders() {
        return identityProviders;
    }

    public void setIdentityProviders(Collection<SpidRegistration> localIdpRegistry) {
        Set<SpidRegistration> identityProviders = new HashSet<>();

        // identity providers must be defined either in the configMap via url or in the application configuration (local registry)
        if (StringUtils.hasText(configMap.getIdpMetadataUrl())) {
            // single idp via url
            SpidRegistration reg = null;

            if (localIdpRegistry != null) {
                reg = localIdpRegistry
                    .stream()
                    .filter(idp -> idp.getMetadataUrl().equals(configMap.getIdpMetadataUrl()))
                    .findFirst().orElse(null);
            } 
            if (reg == null) {
                try {
                    // build its relying party registration and create a default SpidRegistration
                    RelyingPartyRegistration apReg = toRelyingPartyRegistration(configMap.getIdpMetadataUrl(), configMap.getIdpMetadataUrl(), true);
                    String idpEntityId = apReg.getAssertingPartyDetails().getEntityId();

                    reg = new SpidRegistration();
                    reg.setEntityId(idpEntityId);
                    reg.setEntityName(idpEntityId);
                    reg.setMetadataUrl(configMap.getIdpMetadataUrl());
                    reg.setEntityLabel(idpEntityId);
                } catch (IOException | CertificateException e) {
				    // skip that registration if that idp is offline
			    }
            }
            if (reg != null) {
                identityProviders.add(reg);
            }
        } else if (localIdpRegistry != null) {
            // multiple idps via local registry
            // if config map defined some specific idps, pick those, otherwise pick all
            if (configMap.getIdps() != null && !configMap.getIdps().isEmpty()) {
                localIdpRegistry.stream()
                    .filter(idp -> configMap.getIdps().contains(idp.getEntityId()))
                    .forEach(idp -> identityProviders.add(idp));
            } else {
                identityProviders.addAll(localIdpRegistry);
            }
        }

        if (identityProviders.isEmpty()) {
            throw new IllegalArgumentException("invalid configuration: no defined upstream spid idps");
        }

        this.identityProviders = identityProviders;
    }

    /*
     * getRelyingPartyRegistration yields a single relying party registration 
     * with registration id equal to the encoded providerId.
     * This is required for cases where the registration does not require any asserting party details,
     * such as SPID metadata.
     */
    @JsonIgnore
    public RelyingPartyRegistration getRelyingPartyRegistration() {
        if (relyingPartyRegistrations != null) {
            String registrationId = getMetadataRegistrationId();
            RelyingPartyRegistration r = relyingPartyRegistrations
                .stream()
                .filter(reg -> reg.getRegistrationId().equals(registrationId))
                .findFirst().orElse(null);

            if (r != null) {
                return r;
            }
        }

        try {
            RelyingPartyRegistration r = toBareRelyingPartyRegistration(true);
            if (relyingPartyRegistrations == null) {
                relyingPartyRegistrations = new HashSet<>();
            }
            relyingPartyRegistrations.add(r);
            return r;
        } catch (IOException | CertificateException e) {
            throw new RuntimeException("error building registration: " + e.getMessage());
        }
    }

    /*
     * getRelyingPartyRegistration yields a single relying party registration 
     * for the configured upstream identity provider associated to the input idpKey
     */
    @JsonIgnore
    public RelyingPartyRegistration getRelyingPartyRegistration(String idpKey) {
        if (relyingPartyRegistrations != null) {
            String registrationId = encodeRegistrationId(evalRelyingPartyRegistrationId(idpKey));
            RelyingPartyRegistration r = relyingPartyRegistrations
                .stream()
                .filter(reg -> reg.getRegistrationId().equals(registrationId))
                .findFirst().orElse(null);

            if (r != null) {
                return r;
            }
        }

        try {
            String idpMetadataUrl = getAssertingPartyMetadataUrl(idpKey);
            String registrationId = encodeRegistrationId(evalRelyingPartyRegistrationId(evalIdpKeyIdentifier(idpMetadataUrl)));
            RelyingPartyRegistration r = toRelyingPartyRegistration(registrationId, idpMetadataUrl, true);
            if (relyingPartyRegistrations == null) {
                relyingPartyRegistrations = new HashSet<>();
            }
            relyingPartyRegistrations.add(r);
            return r;
        } catch (IOException | CertificateException | URISyntaxException e) {
            throw new RuntimeException("error building registration: " + e.getMessage());
        }
    }

    /*
     * getMetadataRelyingPartyRegistration yields a single relying party registration 
     * with registration id equal to the encoded providerId.
     * This is required for cases where the registration does not require any asserting party details,
     * such as SPID metadata.
     * It differs from getRelyingPartyRegistration as it uses the metadataRelyingPartyRegistrations set
     * to store registrations built with the full set of signing certificates instead of the single active one.
     */
    @JsonIgnore
    public RelyingPartyRegistration getMetadataRelyingPartyRegistration() {
        if (metadataRelyingPartyRegistrations != null) {
            String registrationId = getMetadataRegistrationId();
            RelyingPartyRegistration r = metadataRelyingPartyRegistrations
                .stream()
                .filter(reg -> reg.getRegistrationId().equals(registrationId))
                .findFirst().orElse(null);

            if (r != null) {
                return r;
            }
        }

        try {
            RelyingPartyRegistration r = toBareRelyingPartyRegistration(false);
            if (metadataRelyingPartyRegistrations == null) {
                metadataRelyingPartyRegistrations = new HashSet<>();
            }
            metadataRelyingPartyRegistrations.add(r);
            return r;
        } catch (IOException | CertificateException e) {
            throw new RuntimeException("error building registration: " + e.getMessage());
        }
    }

    /*
     * getMetadataRelyingPartyRegistration yields a single relying party registration 
     * for the configured upstream identity provider associated to the input idpKey.
     * It differs from getRelyingPartyRegistration as it uses the metadataRelyingPartyRegistrations set
     * to store registrations built with the full set of signing certificates instead of the single active one.
     */
    @JsonIgnore
    public RelyingPartyRegistration getMetadataRelyingPartyRegistration(String idpKey) {
        if (metadataRelyingPartyRegistrations != null) {
            String registrationId = encodeRegistrationId(evalRelyingPartyRegistrationId(idpKey));
            RelyingPartyRegistration r = metadataRelyingPartyRegistrations
                .stream()
                .filter(reg -> reg.getRegistrationId().equals(registrationId))
                .findFirst().orElse(null);

            if (r != null) {
                return r;
            }
        }

        try {
            String idpMetadataUrl = getAssertingPartyMetadataUrl(idpKey);
            String registrationId = encodeRegistrationId(evalRelyingPartyRegistrationId(evalIdpKeyIdentifier(idpMetadataUrl)));
            RelyingPartyRegistration r = toRelyingPartyRegistration(registrationId, idpMetadataUrl, false);
            if (metadataRelyingPartyRegistrations == null) {
                metadataRelyingPartyRegistrations = new HashSet<>();
            }
            metadataRelyingPartyRegistrations.add(r);
            return r;
        } catch (IOException | CertificateException | URISyntaxException e) {
            throw new RuntimeException("error building registration: " + e.getMessage());
        }
    }

    // create a relying party registration with placeholder ap configuration.
    private RelyingPartyRegistration toBareRelyingPartyRegistration(boolean onlyActiveCredential) throws IOException, CertificateException {
        RelyingPartyRegistration.Builder builder = RelyingPartyRegistration
            .withRegistrationId(getMetadataRegistrationId())
            .entityId(getEntityId())
            .assertionConsumerServiceLocation(getConsumerUrl())
            .assertionConsumerServiceBinding(Saml2MessageBinding.POST)
            .singleLogoutServiceLocation(getLogoutUrl());
        
        builder.assertingPartyDetails(party -> 
            party
                .entityId("http://placeholder.entity.id")
                .singleSignOnServiceLocation("http://placeholder.sso.location")
        );

        builder = buildSigningCredentials(builder, onlyActiveCredential);
        return builder.build();
    }

    // create a relying party registration for an upstream idp; only ap autoconfiguration is supported,
    // hence function parameters require an idp metadata url
    private RelyingPartyRegistration toRelyingPartyRegistration(String registrationId, String idpMetadataUrl, boolean onlyActiveCredential) throws IOException, CertificateException {
        // start from ap autoconfiguration ...
        RelyingPartyRegistration.Builder builder = RelyingPartyRegistrations
            .fromMetadataLocation(idpMetadataUrl)
            .registrationId(registrationId);

        // ... then expand with rp configuration (i.e. ourself)
        builder
            .entityId(getEntityId())
            .assertionConsumerServiceLocation(getConsumerUrl())
            .assertionConsumerServiceBinding(Saml2MessageBinding.POST)
            .singleLogoutServiceLocation(getLogoutUrl());

        builder = buildSigningCredentials(builder, onlyActiveCredential);
        return builder.build();
    }

    private RelyingPartyRegistration.Builder buildSigningCredentials(RelyingPartyRegistration.Builder builder, boolean onlyActiveCredential) throws IOException, CertificateException {

        List<SigningCredential> signingCredentialList = signingCredentialList(onlyActiveCredential);

        for (SigningCredential signingCredential : signingCredentialList) {
            String signingKey = signingCredential.getSigningKey();
            String signingCertificate = signingCredential.getSigningCertificate();

            if (StringUtils.hasText(signingKey) && StringUtils.hasText(signingCertificate)) {
                // only RSA keys are supported
                Saml2X509Credential credential = CertificateParser.genCredentials(
                    signingKey,
                    signingCertificate,
                    Saml2X509Credential.Saml2X509CredentialType.SIGNING,
                    Saml2X509Credential.Saml2X509CredentialType.DECRYPTION
                );
                builder.signingX509Credentials(c -> c.add(credential));
            }
        }

        return builder;
    }

    private List<SigningCredential> signingCredentialList(boolean onlyActiveCredential) throws IOException, CertificateException {
        List<SigningCredential> signingCredentialList = new ArrayList<>();

        if (StringUtils.hasText(configMap.getSigningKey()) && StringUtils.hasText(configMap.getSigningCertificate())) {
            signingCredentialList.add(new SigningCredential(null, configMap.getSigningKey(), configMap.getSigningCertificate()));
        }

        if (onlyActiveCredential && signingCredentialList.isEmpty() && configMap.getSigningCredentials() != null && !configMap.getSigningCredentials().isEmpty()) {
            String activeSigningCredentialId = configMap.getActiveSigningCredentialId();
            List<SigningCredential> allCredentials = configMap.getSigningCredentials();

            SigningCredential credential = allCredentials.stream()
                    .filter(c -> StringUtils.hasText(activeSigningCredentialId) && activeSigningCredentialId.equals(c.getCredentialId()))
                    .findFirst()
                    .orElse(null);

            if(credential == null){
                credential = allCredentials.get(0);
            }

            checkValidSigningCredential(signingCredentialList, credential);
        }else if (!onlyActiveCredential){
            if (configMap.getSigningCredentials() != null) {
                for(SigningCredential credential: configMap.getSigningCredentials()){
                    checkValidSigningCredential(signingCredentialList, credential);
                }
            }
        }

        if (signingCredentialList.isEmpty()) {
            throw new IllegalArgumentException("CRITICAL: Missing SPID signing credentials. " +
                    "The Service Provider cannot establish a Circle of Trust with IdPs " +
                    "as required by AgID technical regulations (Binding HTTP-POST/Redirect).");
        }

        return signingCredentialList;
    }

    private void checkValidSigningCredential(List<SigningCredential> signingCredentialList, SigningCredential credential){
        if (StringUtils.hasText(credential.getSigningKey()) && StringUtils.hasText(credential.getSigningCertificate())) {
            signingCredentialList.add(credential);
        }
    }

    private void validateSigningCredentials() {
        try {
            signingCredentialList(true);
        } catch (IOException | CertificateException e) {
            throw new IllegalArgumentException("failed to validate SigningCredentials: " + e.getMessage(), e);
        }
    }

    // yield a unique key per upstream metadata (url)
    // the key is fetched from configuration file (is present), otherwise host is used
    // the function might throws an exception if the provided the metadata url is not
    // a valid uri
    public String evalIdpKeyIdentifier(String idpMetadataUrl) throws URISyntaxException {
        SpidRegistration reg = identityProviders
            .stream()
            .filter(idp -> idp.getMetadataUrl().equals(idpMetadataUrl))
            .findFirst().orElse(null);;

        if (reg != null) {
            return reg.getEntityId();
        }
        return new URI(idpMetadataUrl).getHost();
    }

    // obtain an allegedly unique identifier from an idp key; this identifier can be used
    // to identify a relying party registration
    public String evalRelyingPartyRegistrationId(String idpKeyIdentifier) {
        // NOTE: this function is 'inverted' by getProviderId(..)
        return getProvider() + "|" + idpKeyIdentifier;
    }

    public String getConsumerUrl() {
        return "{baseUrl}" + SpidIdentityAuthority.AUTHORITY_URL + "sso/" + getMetadataRegistrationId();
    }

    public String getLogoutUrl() {
        return "{baseUrl}" + SpidIdentityAuthority.AUTHORITY_URL + "slo/" + getMetadataRegistrationId();
    }

    private String getMetadataRegistrationId() {
        return encodeRegistrationId(getProvider());
    }

    public static String encodeRegistrationId(String regId) {
        return Base64.getUrlEncoder().encodeToString(regId.getBytes());
    }

    public static String decodeRegistrationId(String encodedRegId) {
        return new String(Base64.getUrlDecoder().decode(encodedRegId), StandardCharsets.UTF_8);
    }

    @JsonIgnore
    public List<Credential> getMetadataRelyingPartySigningCredentials() {
        List<Credential> credentials = new ArrayList<>();
        RelyingPartyRegistration rp = getMetadataRelyingPartyRegistration();
        if (rp == null) {
            return credentials;
        }
        for (Saml2X509Credential x509Credential : rp.getSigningX509Credentials()) {
            X509Certificate certificate = x509Credential.getCertificate();
            PrivateKey privateKey = x509Credential.getPrivateKey();
            BasicCredential credential = CredentialSupport.getSimpleCredential(certificate, privateKey);
            credential.setEntityId(rp.getEntityId());
            credential.setUsageType(UsageType.SIGNING);
            credentials.add(credential);
        }
        return credentials;
    }

    // additional properties not supported by stock model
    public Boolean getRelyingPartyRegistrationIsForceAuthn() {
        // According to specs, ForceAuthn cannot be chosen for SpidL2 or SpidL3

        // return always true due to check in spid validator
        return true;
    }

    public String getEntityId() {
        return metadataConfiguration.getEntityId() != null
            ? metadataConfiguration.getEntityId()
            : getMetadataUrl();
    }

    public Set<SpidAttributeConsumingService> getAttributeConsumingServices() {
        return metadataConfiguration.getAttributeConsumingServices() != null
            ? metadataConfiguration.getAttributeConsumingServices()
            : Collections.emptySet();
    }

    public String getOrganizationName() {
        return metadataConfiguration.getOrganizationName();
    }

    public String getOrganizationDisplayName() {
        return metadataConfiguration.getOrganizationDisplayName();
    }

    public String getOrganizationUrl() {
        return metadataConfiguration.getOrganizationUrl();
    }

    public String getContactPersonEmailAddress() {
        return metadataConfiguration.getContactPersonEmailAddress();
    }

    public String getContactPersonIPACode() {
        return metadataConfiguration.getContactPersonIPACode();
    }

    public Boolean getUseAssertionConsumerServiceUrl() {
        return configMap.getUseAssertionConsumerServiceUrl() != null
            && configMap.getUseAssertionConsumerServiceUrl();
    }

    public Integer getAttributeConsumingServiceIndex() {
        return configMap.getAttributeConsumingServiceIndex() != null
            ? configMap.getAttributeConsumingServiceIndex()
            : DEFAULT_ATTRIBUTE_CONSUMING_SERVICE_INDEX;
    }

    public Set<String> getRelyingPartyRegistrationAuthnContextClassRefs() {
        return configMap.getAuthnContext() == null
            ? Collections.emptySet()
            : Collections.singleton(configMap.getAuthnContext().getValue());
    }

    public SpidUserAttribute getSubAttributeName() {
        return configMap.getSubAttributeName();
    }

    public SpidUserAttribute getUsernameAttributeName() {
        return configMap.getUsernameAttributeName();
    }

    public Set<String> getRelyingPartyRegistrationIds() {
        Set<String> ids = new HashSet<>();

        identityProviders.stream().forEach(
            idp -> ids.add(encodeRegistrationId(evalRelyingPartyRegistrationId(idp.getEntityId())))
        );
        ids.add(getMetadataRegistrationId());
        return ids;
    }

    private String getAssertingPartyMetadataUrl(String idpEntityId) {
        SpidRegistration reg = identityProviders
            .stream()
            .filter(idp -> idp.getEntityId().equals(idpEntityId))
            .findFirst().orElse(null);
        
        if (reg != null) {
            return reg.getMetadataUrl();
        }
        return null;
    }

    private void loadMetadataConfiguration() {
        if (StringUtils.hasText(configMap.getMetadataUrl())) {
            try {
                this.metadataConfiguration = getMetadataConfigurationFromUrl(configMap.getMetadataUrl());
            } catch (IOException e) {
                throw new IllegalArgumentException("failed to download metadata from URL: " + e.getMessage(), e);
            }
        } else if (StringUtils.hasText(configMap.getMetadataXML())) {
            this.metadataConfiguration = getMetadataConfigurationFromXML(configMap.getMetadataXML());
        } else {
            Set<SpidAttributeConsumingService> attributeConsumingServices = new HashSet<>();
            if (configMap.getSpidAttributes() != null) {
                attributeConsumingServices.add(new SpidAttributeConsumingService(
                    DEFAULT_ATTRIBUTE_CONSUMING_SERVICE_INDEX,
                    DEFAULT_ATTRIBUTE_CONSUMING_SERVICE_NAME,
                    configMap.getSpidAttributes()
                ));
            }
            this.metadataConfiguration = new SpidMetadataConfiguration(
                configMap.getEntityId(),
                attributeConsumingServices,
                configMap.getOrganizationName(),
                configMap.getOrganizationDisplayName(),
                configMap.getOrganizationUrl(),
                configMap.getContactPersonEmailAddress(),
                configMap.getContactPersonIPACode()
            );
        }

        if (this.metadataConfiguration == null) {
            throw new IllegalArgumentException("empty metadata configuration");
        }
    }

    private SpidMetadataConfiguration getMetadataConfigurationFromUrl(String url) throws IOException {
        if (!StringUtils.hasText(url)) {
            throw new IllegalArgumentException("metadata url is blank");
        }
        ResponseEntity<String> response = getRestTemplate().exchange(url, HttpMethod.GET, null, String.class);
        if (response == null || response.getStatusCode() == null) {
            throw new IOException("failed to fetch metadata, empty response");
        }
        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new IOException("failed to fetch metadata, status: " + response.getStatusCode());
        }
        String xml = response.getBody();
        if (!StringUtils.hasText(xml)) {
            throw new IOException("empty metadata response body");
        }
        return getMetadataConfigurationFromXML(xml);
    }

    private SpidMetadataConfiguration getMetadataConfigurationFromXML(String xml) {
        SpidMetadataConfiguration metadataConfiguration = new SpidMetadataConfiguration();
        try {
            Document doc = parseMetadataXml(xml);
            XPath xpath = newXPath();
            String entityId = (String) xpath.evaluate(XPATH_EXPRESSION_ENTITY_ID, doc, XPathConstants.STRING);
            String organizationName = (String) xpath.evaluate(XPATH_EXPRESSION_ORGANIZATION_NAME, doc, XPathConstants.STRING);
            String organizationDisplayName = (String) xpath.evaluate(XPATH_EXPRESSION_ORGANIZATION_DISPLAY_NAME, doc, XPathConstants.STRING);
            String organizationURL = (String) xpath.evaluate(XPATH_EXPRESSION_ORGANIZATION_URL, doc, XPathConstants.STRING);
            String contactPersonEmailAddress = (String) xpath.evaluate(XPATH_EXPRESSION_CONTACT_PERSON_EMAIL_ADDRESS, doc, XPathConstants.STRING);
            String contactPersonIPACode = (String) xpath.evaluate(XPATH_EXPRESSION_CONTACT_PERSON_IPA_CODE, doc, XPathConstants.STRING);
            
            Set<SpidAttributeConsumingService> attributeConsumingServices = Collections.emptySet();
            NodeList acsList = (NodeList) xpath.evaluate(XPATH_EXPRESSION_ATTRIBUTE_CONSUMING_SERVICES, doc, XPathConstants.NODESET);
            if (acsList != null && acsList.getLength() > 0) {
                attributeConsumingServices = parseAttributeConsumingServicesFromMetadata(acsList, xpath);
            }

            metadataConfiguration.setEntityId(entityId);
            metadataConfiguration.setAttributeConsumingServices(attributeConsumingServices);
            metadataConfiguration.setOrganizationName(organizationName);
            metadataConfiguration.setOrganizationDisplayName(organizationDisplayName);
            metadataConfiguration.setOrganizationUrl(organizationURL);
            metadataConfiguration.setContactPersonEmailAddress(contactPersonEmailAddress);
            metadataConfiguration.setContactPersonIPACode(contactPersonIPACode);

            // verify metadata X509Certificate against configured signingCertificate
            verifyX509Certificate(doc, xpath);
            
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid metadata XML: " + e.getMessage(), e);
        }

        return metadataConfiguration;
    }

    private Set<SpidAttributeConsumingService> parseAttributeConsumingServicesFromMetadata(NodeList acsList, XPath xpath) throws XPathExpressionException {
        Set<SpidAttributeConsumingService> attributeConsumingServices = new HashSet<>();

        for (int i = 0; i < acsList.getLength(); i++) {
            Element acs = (Element) acsList.item(i);
            
            String index = acs.getAttribute("index");
            String serviceName = (String) xpath.evaluate(XPATH_EXPRESSION_ACS_SERVICE_NAME, acs, XPathConstants.STRING);

            Set<SpidAttribute> attributes = new HashSet<>();
            NodeList attrList = (NodeList) xpath.evaluate(XPATH_EXPRESSION_ACS_REQUESTED_ATTRIBUTE, acs, XPathConstants.NODESET);
            for (int j = 0; j < attrList.getLength(); j++) {
                Element attr = (Element) attrList.item(j);

                String name = attr.getAttribute("Name");
                SpidAttribute attribute = SpidAttribute.parse(name);
                if (attribute != null) {
                    attributes.add(attribute);
                }
            }

            SpidAttributeConsumingService attributeConsumingService = new SpidAttributeConsumingService(Integer.parseInt(index), serviceName, attributes);
            attributeConsumingServices.add(attributeConsumingService);
        }

        Integer index = getAttributeConsumingServiceIndex();
        Boolean indexExists = attributeConsumingServices.stream().anyMatch(acs -> index.equals(acs.getIndex()));
        if (!indexExists) {
            throw new IllegalArgumentException("configured attribute consuming service index not present in metadata attribute consuming services");
        }

        return attributeConsumingServices;
    }

    private void verifyX509Certificate(Document doc, XPath xpath) throws XPathExpressionException, CertificateException, IOException {
        NodeList metaCertList = (NodeList) xpath.evaluate(XPATH_EXPRESSION_SIGNING_CERTIFICATES, doc, XPathConstants.NODESET);
        if (metaCertList == null || metaCertList.getLength() == 0) {
            throw new IllegalArgumentException("empty signing certificate in metadata");
        }

        Set<String> metaCertNormalizedList = new HashSet<>();
        for (int i = 0; i < metaCertList.getLength(); i++) {
            String metaCert = metaCertList.item(i).getTextContent();
            String metaCertNormalized = stripPem(metaCert);
            if (StringUtils.hasText(metaCertNormalized)) {
                metaCertNormalizedList.add(metaCertNormalized);
            }
        }
        if (metaCertNormalizedList.isEmpty()) {
            throw new IllegalArgumentException("no valid signing certificates found in metadata");
        }

        List<SigningCredential> signingCredentialList = signingCredentialList(false);

        Set<String> confCertNormalizedList = signingCredentialList
            .stream()
            .map(SigningCredential::getSigningCertificate)
            .filter(StringUtils::hasText)
            .map(c -> stripPem(c))
            .collect(Collectors.toSet());
        
        if (!metaCertNormalizedList.equals(confCertNormalizedList)) {
            throw new IllegalArgumentException("configured signingCertificate not present in metadata signing X509Certificate");
        }
    }

    private Document parseMetadataXml(String xml) throws ParserConfigurationException, IOException, SAXException {
        if (!StringUtils.hasText(xml)) {
            throw new IllegalArgumentException("no metadata XML configured");
        }
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        try (ByteArrayInputStream bais = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8))) {
            return db.parse(bais);
        }
    }

    private XPath newXPath() {
        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new NamespaceContext() {
            @Override
            public String getNamespaceURI(String prefix) {
                switch (prefix) {
                    case "md":
                        return "urn:oasis:names:tc:SAML:2.0:metadata";
                    case "ds":
                        return "http://www.w3.org/2000/09/xmldsig#";
                    case "spid":
                        return "https://spid.gov.it/saml-extensions";
                    case "xml":
                        return "http://www.w3.org/XML/1998/namespace";
                    default:
                        return javax.xml.XMLConstants.NULL_NS_URI;
                }
            }

            @Override
            public String getPrefix(String namespaceURI) {
                return null;
            }

            @Override
            public Iterator<String> getPrefixes(String namespaceURI) {
                return null;
            }
        });
        return xpath;
    }

    private String stripPem(String cert) {
        if (cert == null) return null;
        return cert
            .replaceAll("-----BEGIN CERTIFICATE-----", "")
            .replaceAll("-----END CERTIFICATE-----", "")
            .replaceAll("\\s+", "");
    }

    private RestTemplate getRestTemplate() {
        if (restTemplate == null) {
            RequestConfig rconfig = RequestConfig
                .custom()
                .setConnectTimeout(DEFAULT_TIMEOUT)
                .setConnectionRequestTimeout(DEFAULT_TIMEOUT)
                .setSocketTimeout(DEFAULT_TIMEOUT)
                .build();
            CloseableHttpClient client = HttpClientBuilder.create().setDefaultRequestConfig(rconfig).build();
            HttpComponentsClientHttpRequestFactory clientHttpRequestFactory = new HttpComponentsClientHttpRequestFactory(client);
            restTemplate = new RestTemplate(clientHttpRequestFactory);
        }
        return restTemplate;
    }
}
