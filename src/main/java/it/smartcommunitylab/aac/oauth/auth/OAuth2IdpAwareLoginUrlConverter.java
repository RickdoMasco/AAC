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

package it.smartcommunitylab.aac.oauth.auth;

import it.smartcommunitylab.aac.common.NoSuchAuthorityException;
import it.smartcommunitylab.aac.common.NoSuchProviderException;
import it.smartcommunitylab.aac.core.auth.LoginUrlRequestConverter;
import it.smartcommunitylab.aac.identity.model.ConfigurableIdentityProvider;
import it.smartcommunitylab.aac.identity.provider.IdentityProvider;
import it.smartcommunitylab.aac.identity.service.IdentityProviderAuthorityService;
import it.smartcommunitylab.aac.identity.service.IdentityProviderService;
import it.smartcommunitylab.aac.oauth.service.OAuth2ClientService;

import java.util.Collection;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class OAuth2IdpAwareLoginUrlConverter implements LoginUrlRequestConverter {

    public static final String IDP_PARAMETER_NAME = "idp_hint";

    private final IdentityProviderService providerService;
    private final IdentityProviderAuthorityService authorityService;
    private final OAuth2ClientService clientService;

    public OAuth2IdpAwareLoginUrlConverter(
        IdentityProviderService providerService,
        IdentityProviderAuthorityService authorityService,
        OAuth2ClientService clientService
    ) {
        Assert.notNull(providerService, "provider service is required");
        Assert.notNull(authorityService, "authority service is required");

        this.authorityService = authorityService;
        this.providerService = providerService;
        this.clientService = clientService;
    }

    @Override
    public String convert(
        HttpServletRequest request,
        HttpServletResponse response,
        AuthenticationException authException
    ) {
        // check if idp hint via param
        String idpHint = null;
        if (request.getParameter(IDP_PARAMETER_NAME) != null) {
            idpHint = request.getParameter(IDP_PARAMETER_NAME);
        }

        // check if idp hint via attribute
        if (request.getAttribute(IDP_PARAMETER_NAME) != null) {
            idpHint = (String) request.getAttribute(IDP_PARAMETER_NAME);
        }

        // check if idp hint
        if (StringUtils.hasText(idpHint)) {
            // TODO check for idpHint == authorityId
            // needs discoverable realm either via path or via clientId

            ConfigurableIdentityProvider idp = null;
            try {
                idp = providerService.getProvider(idpHint);
                // TODO check if active
            } catch (NoSuchProviderException e) {
                // try to resolve by realm + clientId
                String clientId = null;
                if (request.getParameter(OAuth2ParameterNames.CLIENT_ID) != null) {
                    clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
                }
                if (!StringUtils.hasText(clientId)) {
                    return null;
                }

                String realm = clientService.findClient(clientId) != null
                    ? clientService.findClient(clientId).getRealm()
                    : null;

                if (!StringUtils.hasText(realm)) {
                    return null;
                }

                Collection<ConfigurableIdentityProvider> providers = providerService.listProviders(realm);
                for (ConfigurableIdentityProvider p : providers) {
                    if (p.getName().equals(idpHint)) {
                        idp = p;
                        break;
                    }
                }
                if (idp == null) {
                    // not found
                    return null;
                }
            }

            try {               
                // fetch providers for given realm
                IdentityProvider<?, ?, ?, ?, ?> provider = authorityService
                    .getAuthority(idp.getAuthority())
                    .getProvider(idp.getProvider());
                if (provider == null) {
                    throw new NoSuchProviderException();
                }

                return provider.getAuthenticationUrl(request);
            } catch (NoSuchAuthorityException | NoSuchProviderException e) {
                // no valid response
                return null;
            }
        }

        // not found
        return null;
    }
}
