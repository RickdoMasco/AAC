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

package it.smartcommunitylab.aac.openidfed.service;

import it.smartcommunitylab.aac.SystemKeys;
import it.smartcommunitylab.aac.accounts.AccountServiceAuthority;
import it.smartcommunitylab.aac.accounts.model.ConfigurableAccountService;
import it.smartcommunitylab.aac.accounts.persistence.UserAccountService;
import it.smartcommunitylab.aac.accounts.provider.AccountServiceSettingsMap;
import it.smartcommunitylab.aac.base.authorities.AbstractProviderAuthority;
import it.smartcommunitylab.aac.core.provider.ConfigurationProvider;
import it.smartcommunitylab.aac.core.provider.ProviderConfigRepository;
import it.smartcommunitylab.aac.core.service.ResourceEntityService;
import it.smartcommunitylab.aac.core.service.TranslatorProviderConfigRepository;
import it.smartcommunitylab.aac.oidc.model.OIDCEditableUserAccount;
import it.smartcommunitylab.aac.oidc.model.OIDCUserAccount;
import it.smartcommunitylab.aac.openidfed.provider.OpenIdFedAccountService;
import it.smartcommunitylab.aac.openidfed.provider.OpenIdFedAccountServiceConfig;
import it.smartcommunitylab.aac.openidfed.provider.OpenIdFedAccountServiceConfigConverter;
import it.smartcommunitylab.aac.openidfed.provider.OpenIdFedIdentityProviderConfig;
import it.smartcommunitylab.aac.openidfed.provider.OpenIdFedIdentityProviderConfigMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

@Service
public class OpenIdFedAccountServiceAuthority
    extends AbstractProviderAuthority<OpenIdFedAccountService, OpenIdFedAccountServiceConfig>
    implements
        AccountServiceAuthority<OpenIdFedAccountService, OIDCUserAccount, OIDCEditableUserAccount, OpenIdFedAccountServiceConfig, OpenIdFedIdentityProviderConfigMap> {

    // account service
    private final UserAccountService<OIDCUserAccount> accountService;
    private ResourceEntityService resourceService;

    @Autowired
    public OpenIdFedAccountServiceAuthority(
        UserAccountService<OIDCUserAccount> userAccountService,
        ProviderConfigRepository<OpenIdFedIdentityProviderConfig> registrationRepository
    ) {
        super(SystemKeys.AUTHORITY_OPENIDFED, new OpenIdFedConfigTranslatorRepository(registrationRepository));
        Assert.notNull(userAccountService, "account service is mandatory");

        this.accountService = userAccountService;
    }

    @Autowired
    public void setResourceService(ResourceEntityService resourceService) {
        this.resourceService = resourceService;
    }

    protected OpenIdFedAccountService buildProvider(OpenIdFedAccountServiceConfig config) {
        OpenIdFedAccountService service = new OpenIdFedAccountService(
            config.getProvider(),
            accountService,
            config,
            config.getRealm()
        );
        service.setResourceService(resourceService);

        return service;
    }

    static class OpenIdFedConfigTranslatorRepository
        extends TranslatorProviderConfigRepository<OpenIdFedIdentityProviderConfig, OpenIdFedAccountServiceConfig> {

        public OpenIdFedConfigTranslatorRepository(ProviderConfigRepository<OpenIdFedIdentityProviderConfig> externalRepository) {
            super(externalRepository);
            setConverter(new OpenIdFedAccountServiceConfigConverter());
        }
    }

    @Override
    public ConfigurationProvider<OpenIdFedAccountServiceConfig, ConfigurableAccountService, AccountServiceSettingsMap, OpenIdFedIdentityProviderConfigMap> getConfigurationProvider() {
        return null;
    }
}
