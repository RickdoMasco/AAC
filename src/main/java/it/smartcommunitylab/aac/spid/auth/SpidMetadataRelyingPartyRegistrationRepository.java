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

package it.smartcommunitylab.aac.spid.auth;

import it.smartcommunitylab.aac.core.provider.ProviderConfigRepository;
import it.smartcommunitylab.aac.spid.provider.SpidIdentityProviderConfig;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.util.Assert;

/*
 * SpidMetadataRelyingPartyRegistrationRepository is a repository of relying party registrations
 * specifically for SPID metadata.
 * The current implementation retrieves the provider-wide registration by identifying
 * the provider via the encoded registrationId.
 * Since metadata is unified, it ignores the optional entity label pattern.
 */
public class SpidMetadataRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository {

    private final ProviderConfigRepository<SpidIdentityProviderConfig> providerConfigRepository;

    public SpidMetadataRelyingPartyRegistrationRepository(
        ProviderConfigRepository<SpidIdentityProviderConfig> providerConfigRepository
    ) {
        Assert.notNull(providerConfigRepository, "provider registration repository can not be null");
        this.providerConfigRepository = providerConfigRepository;
    }

    /*
     * findByRegistrationId provides read access as per interface.
     * Spid supports two different patterns for registration ids:
     * (1) {providerId}
     * The function extracts the providerId to return the correct
     * provider-wide metadata registration.
     */
    @Override
    public RelyingPartyRegistration findByRegistrationId(String registrationId) {
        Assert.hasText(registrationId, "registration id can not be empty");

        // Extract the providerId (handles both patterns to find the owner)
        String providerId = SpidIdentityProviderConfig.decodeRegistrationId(registrationId);

        SpidIdentityProviderConfig providerConfig = providerConfigRepository.findByProviderId(providerId);
        if (providerConfig == null) {
            return null;
        }

        return providerConfig.getMetadataRelyingPartyRegistration();
    }
}
