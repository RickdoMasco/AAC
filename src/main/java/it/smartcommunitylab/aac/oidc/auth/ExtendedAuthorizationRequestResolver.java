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

package it.smartcommunitylab.aac.oidc.auth;

import it.smartcommunitylab.aac.core.provider.ProviderConfigRepository;
import it.smartcommunitylab.aac.oauth.model.PromptMode;
import it.smartcommunitylab.aac.oidc.provider.OIDCIdentityProviderConfig;
import it.smartcommunitylab.aac.oidc.provider.OIDCIdentityProviderConfigMap.CustomAuthNParameter;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.util.StringUtils;

public class ExtendedAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private final ProviderConfigRepository<OIDCIdentityProviderConfig> registrationRepository;
    private final OAuth2AuthorizationRequestResolver resolver;

    public ExtendedAuthorizationRequestResolver(
        OAuth2AuthorizationRequestResolver resolver,
        ProviderConfigRepository<OIDCIdentityProviderConfig> registrationRepository
    ) {
        this.resolver = resolver;
        this.registrationRepository = registrationRepository;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        return enhance(request, resolver.resolve(request));
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        return enhance(request, resolver.resolve(request, clientRegistrationId));
    }

    public OAuth2AuthorizationRequest enhance(HttpServletRequest request, OAuth2AuthorizationRequest authRequest) {
        if (authRequest == null) {
            return null;
        }

        String providerId = authRequest.getAttribute(OAuth2ParameterNames.REGISTRATION_ID);
        if (!StringUtils.hasText(providerId)) {
            return null;
        }

        OIDCIdentityProviderConfig provider = registrationRepository.findByProviderId(providerId);

        // fetch paramers from resolved request
        Map<String, Object> attributes = new HashMap<>(authRequest.getAttributes());
        Map<String, Object> additionalParameters = new HashMap<>(authRequest.getAdditionalParameters());

        if (provider.getConfigMap().getPromptMode() != null) {
            addPromptParameters(provider.getConfigMap().getPromptMode(), additionalParameters);
        }

        if (provider.getConfigMap().getCustomAuthNParameters() != null) {
            addCustomParameters(provider.getConfigMap().getCustomAuthNParameters(), additionalParameters, request);
        }

        // get a builder and reset parameters
        return OAuth2AuthorizationRequest
            .from(authRequest)
            .attributes(attributes)
            .additionalParameters(additionalParameters)
            .build();
    }

    private void addPromptParameters(Set<PromptMode> promptMode, Map<String, Object> additionalParameters) {
        String prompt = StringUtils.collectionToDelimitedString(promptMode, " ");
        if (StringUtils.hasText(prompt)) {
            additionalParameters.put("prompt", prompt);
        }
    }

    private void addCustomParameters(Set<CustomAuthNParameter> customParametes, Map<String, Object> additionalParameters, HttpServletRequest request) {
        // only parameters defined in the provider config can be added
        for (CustomAuthNParameter param : customParametes) {
            if (!StringUtils.hasText(param.getName()) || !isCustomParameterAllowed(param.getName())) {
                continue;
            }

            // resolve parameter value from request, otherwise use default from config if present
            String value = request.getParameter(param.getName());

            if (value != null) {
                additionalParameters.put(param.getName(), value);
            } else if (StringUtils.hasText(param.getValue())) {
                additionalParameters.put(param.getName(), param.getValue());
            }
        }
    }

    private Boolean isCustomParameterAllowed(String name) {
        // prevent overwriting standard parameters
        Set<String> standardParams = Set.of(
            OAuth2ParameterNames.CLIENT_ID,
            OAuth2ParameterNames.RESPONSE_TYPE,
            OAuth2ParameterNames.SCOPE,
            OAuth2ParameterNames.STATE,
            OAuth2ParameterNames.REDIRECT_URI,
            PkceParameterNames.CODE_CHALLENGE,
            PkceParameterNames.CODE_CHALLENGE_METHOD,
            OidcParameterNames.NONCE
        );
        return !standardParams.contains(name);
    }
}
