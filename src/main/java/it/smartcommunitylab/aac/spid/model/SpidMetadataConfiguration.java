package it.smartcommunitylab.aac.spid.model;

import java.io.Serializable;
import java.util.Set;

import javax.validation.Valid;
import javax.validation.constraints.Pattern;

import it.smartcommunitylab.aac.SystemKeys;

@Valid
public class SpidMetadataConfiguration implements Serializable{
    
    private String entityId;

    private Set<SpidAttributeConsumingService> attributeConsumingServices;

    private String organizationName;
    private String organizationDisplayName;
    private String organizationUrl;

    @Pattern(regexp = SystemKeys.EMAIL_PATTERN)
    private String contactPersonEmailAddress;
    @Pattern(regexp = "^[A-Za-z0-9_]*$")
    private String contactPersonIPACode;

    public SpidMetadataConfiguration() {}

    public SpidMetadataConfiguration(String entityId, Set<SpidAttributeConsumingService> attributeConsumingServices, String organizationName, String organizationDisplayName, String organizationUrl, String contactPersonEmailAddress, String contactPersonIPACode) {
        this.entityId = entityId;
        this.attributeConsumingServices = attributeConsumingServices;
        this.organizationName = organizationName;
        this.organizationDisplayName = organizationDisplayName;
        this.organizationUrl = organizationUrl;
        this.contactPersonEmailAddress = contactPersonEmailAddress;
        this.contactPersonIPACode = contactPersonIPACode;
    }

    public String getEntityId() {
        return entityId;
    }

    public void setEntityId(String entityId) {
        this.entityId = entityId;
    }
    
    public Set<SpidAttributeConsumingService> getAttributeConsumingServices() {
        return attributeConsumingServices;
    }

    public void setAttributeConsumingServices(Set<SpidAttributeConsumingService> attributeConsumingServices) {
        this.attributeConsumingServices = attributeConsumingServices;
    }

    public String getOrganizationName() {
        return organizationName;
    }

    public void setOrganizationName(String organizationName) {
        this.organizationName = organizationName;
    }

    public String getOrganizationDisplayName() {
        return organizationDisplayName;
    }

    public void setOrganizationDisplayName(String organizationDisplayName) {
        this.organizationDisplayName = organizationDisplayName;
    }

    public String getOrganizationUrl() {
        return organizationUrl;
    }

    public void setOrganizationUrl(String organizationUrl) {
        this.organizationUrl = organizationUrl;
    }

    public String getContactPersonEmailAddress() {
        return contactPersonEmailAddress;
    }

    public void setContactPersonEmailAddress(String contactPersonEmailAddress) {
        this.contactPersonEmailAddress = contactPersonEmailAddress;
    }

    public String getContactPersonIPACode() {
        return contactPersonIPACode;
    }

    public void setContactPersonIPACode(String contactPersonIPACode) {
        this.contactPersonIPACode = contactPersonIPACode;
    }
}
