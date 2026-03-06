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

package it.smartcommunitylab.aac.oauth.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ResponseType;
import it.smartcommunitylab.aac.Config;
import it.smartcommunitylab.aac.auth.WithMockUserAuthentication;
import it.smartcommunitylab.aac.bootstrap.BootstrapConfig;
import it.smartcommunitylab.aac.oauth.OAuth2ConfigUtils;
import it.smartcommunitylab.aac.oauth.OAuth2TestConfig.UserRegistration;
import it.smartcommunitylab.aac.oauth.endpoint.AuthorizationEndpoint;
import it.smartcommunitylab.aac.oauth.endpoint.ErrorEndpoint;
import it.smartcommunitylab.aac.oauth.endpoint.TokenEndpoint;
import it.smartcommunitylab.aac.oauth.model.ClientRegistration;
import java.io.Serializable;
import java.util.List;
import java.util.Map;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.maciejwalkowiak.wiremock.spring.ConfigureWireMock;
import com.maciejwalkowiak.wiremock.spring.EnableWireMock;
import com.maciejwalkowiak.wiremock.spring.InjectWireMock;
import com.github.tomakehurst.wiremock.WireMockServer;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;

/*
 * OAuth 2.0 Authorization Code Grant
 * as per RFC6749
 *
 * https://www.rfc-editor.org/rfc/rfc6749#section-4.1
 */

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@EnableWireMock({ @ConfigureWireMock(name = "oauth-client") })
public class AuthorizationCodeGrantTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper mapper;

    @Autowired
    private BootstrapConfig config;

    @InjectWireMock("oauth-client")
    private WireMockServer mockClientServer;

    private String username;
    private String password;
    private String clientId;
    private String clientSecret;
    private String client2Id;
    private String client2Secret;

    @BeforeEach
    public void setUp() {
        if (clientId == null || clientSecret == null || client2Id == null || client2Secret == null) {
            List<ClientRegistration> clients = OAuth2ConfigUtils.with(config).clients();
            assertThat(clients.size()).isGreaterThanOrEqualTo(2);

            ClientRegistration client1 = clients.get(0);
            clientId = client1.getClientId();
            clientSecret = client1.getClientSecret();

            ClientRegistration client2 = clients.get(1);
            client2Id = client2.getClientId();
            client2Secret = client2.getClientSecret();
        }

        if (clientId == null || clientSecret == null) {
            throw new IllegalArgumentException("missing config");
        }

        if (username == null || password == null) {
            UserRegistration user = OAuth2ConfigUtils.with(config).user();
            assertThat(user).isNotNull();

            username = user.getUsername();
            password = user.getPassword();
        }

        if (username == null || password == null) {
            throw new IllegalArgumentException("missing config");
        }
    }

    @Test
    @WithMockUserAuthentication(username = "test", realm = "test")
    public void userAuthWithHttpBasicAuthCodeTest() throws Exception {
        // authorize request
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.RESPONSE_TYPE, ResponseType.CODE.toString());
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        // set empty scopes to avoid fall back to predefined
        params.add(OAuth2ParameterNames.SCOPE, "");

        MockHttpServletRequestBuilder req = MockMvcRequestBuilders
            .get(AUTHORIZE_URL)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .params(params);

        MvcResult res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a forward in response
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String forwardedUrl = res.getResponse().getForwardedUrl();
        assertThat(res.getResponse().getForwardedUrl()).isNotNull().startsWith(AUTHORIZED_URL);

        // keep the same session for the whole request flow
        MockHttpSession session = (MockHttpSession) res.getRequest().getSession();
        assertThat(session).isNotNull();

        // follow forward to fetch response
        req = MockMvcRequestBuilders.get(forwardedUrl).session(session);

        res = this.mockMvc.perform(req).andExpect(status().is3xxRedirection()).andReturn();

        // expect a redirect in response with query
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String redirectedUrl = res.getResponse().getRedirectedUrl();
        assertThat(redirectedUrl).isNotNull();

        // parse as queryString
        assertDoesNotThrow(() -> {
            UriComponentsBuilder.fromUriString(redirectedUrl);
        });

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectedUrl);
        MultiValueMap<String, String> queryParams = builder.build(true).getQueryParams();
        assertThat(queryParams).isNotNull();

        // code
        assertThat(queryParams.get(OAuth2ParameterNames.CODE)).isNotNull().isNotEmpty();
        String code = queryParams.get(OAuth2ParameterNames.CODE).get(0);
        assertThat(code).isNotBlank();

        // make a token request
        params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        params.add(OAuth2ParameterNames.CODE, code);

        req =
            MockMvcRequestBuilders
                .post(TOKEN_URL)
                .with(httpBasic(clientId, clientSecret))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .params(params);

        res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a valid json in response
        assertThat(res.getResponse().getContentAsString()).isNotBlank();

        Map<String, Serializable> response = mapper.readValue(res.getResponse().getContentAsString(), typeRef);
        assertThat(response).isNotEmpty();

        // type bearer
        assertThat(response.get(OAuth2ParameterNames.TOKEN_TYPE)).isNotNull().isInstanceOf(String.class);
        assertThat(response.get(OAuth2ParameterNames.TOKEN_TYPE)).isEqualTo("bearer");

        // access token
        assertThat(response.get(OAuth2ParameterNames.ACCESS_TOKEN)).isNotNull().isInstanceOf(String.class);
        String accessToken = (String) response.get(OAuth2ParameterNames.ACCESS_TOKEN);
        assertThat(accessToken).isNotBlank();

        // scopes is null or empty
        assertThat(response.get(OAuth2ParameterNames.SCOPE))
            .satisfiesAnyOf(
                scope -> assertThat(scope).isNull(),
                scope ->
                    assertThat(scope)
                        .isNotNull()
                        .isInstanceOf(String.class)
                        .asInstanceOf(InstanceOfAssertFactories.STRING)
                        .isBlank()
            );
    }

    @Test
    @WithMockUserAuthentication(username = "test", realm = "test")
    public void userAuthWithHttpBasicHeadersTest() throws Exception {
        // authorize request
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.RESPONSE_TYPE, ResponseType.CODE.toString());
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        // set empty scopes to avoid fall back to predefined
        params.add(OAuth2ParameterNames.SCOPE, "");

        MockHttpServletRequestBuilder req = MockMvcRequestBuilders
            .get(AUTHORIZE_URL)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .params(params);

        MvcResult res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a forward in response
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String forwardedUrl = res.getResponse().getForwardedUrl();
        assertThat(res.getResponse().getForwardedUrl()).isNotNull().startsWith(AUTHORIZED_URL);

        // keep the same session for the whole request flow
        MockHttpSession session = (MockHttpSession) res.getRequest().getSession();
        assertThat(session).isNotNull();

        // follow forward to fetch response
        req = MockMvcRequestBuilders.get(forwardedUrl).session(session);

        res = this.mockMvc.perform(req).andExpect(status().is3xxRedirection()).andReturn();

        // expect a redirect in response with query
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String redirectedUrl = res.getResponse().getRedirectedUrl();
        assertThat(redirectedUrl).isNotNull();

        // parse as queryString
        assertDoesNotThrow(() -> {
            UriComponentsBuilder.fromUriString(redirectedUrl);
        });

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectedUrl);
        MultiValueMap<String, String> queryParams = builder.build(true).getQueryParams();
        assertThat(queryParams).isNotNull();

        // code
        assertThat(queryParams.get(OAuth2ParameterNames.CODE)).isNotNull().isNotEmpty();
        String code = queryParams.get(OAuth2ParameterNames.CODE).get(0);
        assertThat(code).isNotBlank();

        // assert headers
        assertThat(res.getResponse().getHeader(HttpHeaders.CACHE_CONTROL))
            .isNotBlank()
            .contains(CacheControl.noStore().getHeaderValue());
        assertThat(res.getResponse().getHeader(HttpHeaders.PRAGMA))
            .isNotBlank()
            .isEqualTo(CacheControl.noCache().getHeaderValue());

        // make a token request
        params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        params.add(OAuth2ParameterNames.CODE, code);

        req =
            MockMvcRequestBuilders
                .post(TOKEN_URL)
                .with(httpBasic(clientId, clientSecret))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .params(params);

        res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a valid json in response
        assertThat(res.getResponse().getContentAsString()).isNotBlank();

        // assert headers
        assertThat(res.getResponse().getHeader(HttpHeaders.CACHE_CONTROL))
            .isNotBlank()
            .isEqualTo(CacheControl.noStore().getHeaderValue());
        assertThat(res.getResponse().getHeader(HttpHeaders.PRAGMA))
            .isNotBlank()
            .isEqualTo(CacheControl.noCache().getHeaderValue());

        Map<String, Serializable> response = mapper.readValue(res.getResponse().getContentAsString(), typeRef);
        assertThat(response).isNotEmpty();

        // access token
        assertThat(response.get(OAuth2ParameterNames.ACCESS_TOKEN)).isNotNull().isInstanceOf(String.class);
        String accessToken = (String) response.get(OAuth2ParameterNames.ACCESS_TOKEN);
        assertThat(accessToken).isNotBlank();
    }

    @Test
    @WithMockUserAuthentication(username = "test", realm = "test")
    public void userAuthWithFormAuthCodeTest() throws Exception {
        // authorize request
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.RESPONSE_TYPE, ResponseType.CODE.toString());
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        // set empty scopes to avoid fall back to predefined
        params.add(OAuth2ParameterNames.SCOPE, "");

        MockHttpServletRequestBuilder req = MockMvcRequestBuilders
            .get(AUTHORIZE_URL)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .params(params);

        MvcResult res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a forward in response
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String forwardedUrl = res.getResponse().getForwardedUrl();
        assertThat(res.getResponse().getForwardedUrl()).isNotNull().startsWith(AUTHORIZED_URL);

        // keep the same session for the whole request flow
        MockHttpSession session = (MockHttpSession) res.getRequest().getSession();
        assertThat(session).isNotNull();

        // follow forward to fetch response
        req = MockMvcRequestBuilders.get(forwardedUrl).session(session);

        res = this.mockMvc.perform(req).andExpect(status().is3xxRedirection()).andReturn();

        // expect a redirect in response with query
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String redirectedUrl = res.getResponse().getRedirectedUrl();
        assertThat(redirectedUrl).isNotNull();

        // parse as queryString
        assertDoesNotThrow(() -> {
            UriComponentsBuilder.fromUriString(redirectedUrl);
        });

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectedUrl);
        MultiValueMap<String, String> queryParams = builder.build(true).getQueryParams();
        assertThat(queryParams).isNotNull();

        // code
        assertThat(queryParams.get(OAuth2ParameterNames.CODE)).isNotNull().isNotEmpty();
        String code = queryParams.get(OAuth2ParameterNames.CODE).get(0);
        assertThat(code).isNotBlank();

        // make a token request
        params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        params.add(OAuth2ParameterNames.CODE, code);
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        params.add(OAuth2ParameterNames.CLIENT_SECRET, clientSecret);

        req = MockMvcRequestBuilders.post(TOKEN_URL).contentType(MediaType.APPLICATION_FORM_URLENCODED).params(params);

        res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a valid json in response
        assertThat(res.getResponse().getContentAsString()).isNotBlank();

        Map<String, Serializable> response = mapper.readValue(res.getResponse().getContentAsString(), typeRef);
        assertThat(response).isNotEmpty();

        // type bearer
        assertThat(response.get(OAuth2ParameterNames.TOKEN_TYPE)).isNotNull().isInstanceOf(String.class);
        assertThat(response.get(OAuth2ParameterNames.TOKEN_TYPE)).isEqualTo("bearer");

        // access token
        assertThat(response.get(OAuth2ParameterNames.ACCESS_TOKEN)).isNotNull().isInstanceOf(String.class);
        String accessToken = (String) response.get(OAuth2ParameterNames.ACCESS_TOKEN);
        assertThat(accessToken).isNotBlank();

        // scopes is null or empty
        assertThat(response.get(OAuth2ParameterNames.SCOPE))
            .satisfiesAnyOf(
                scope -> assertThat(scope).isNull(),
                scope ->
                    assertThat(scope)
                        .isNotNull()
                        .isInstanceOf(String.class)
                        .asInstanceOf(InstanceOfAssertFactories.STRING)
                        .isBlank()
            );
    }

    @Test
    @WithMockUserAuthentication(username = "test", realm = "test")
    public void userAuthWithScopeAndHttpBasicAuthCodeTest() throws Exception {
        // authorize request
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.RESPONSE_TYPE, ResponseType.CODE.toString());
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        params.add(OAuth2ParameterNames.SCOPE, Config.SCOPE_PROFILE);

        MockHttpServletRequestBuilder req = MockMvcRequestBuilders
            .get(AUTHORIZE_URL)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .params(params);

        MvcResult res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a forward in response
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String forwardedUrl = res.getResponse().getForwardedUrl();
        assertThat(res.getResponse().getForwardedUrl()).isNotNull().startsWith(AUTHORIZED_URL);

        // keep the same session for the whole request flow
        MockHttpSession session = (MockHttpSession) res.getRequest().getSession();
        assertThat(session).isNotNull();

        // follow forward to fetch response
        req = MockMvcRequestBuilders.get(forwardedUrl).session(session);

        res = this.mockMvc.perform(req).andExpect(status().is3xxRedirection()).andReturn();

        // expect a redirect in response with query
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String redirectedUrl = res.getResponse().getRedirectedUrl();
        assertThat(redirectedUrl).isNotNull();

        // parse as queryString
        assertDoesNotThrow(() -> {
            UriComponentsBuilder.fromUriString(redirectedUrl);
        });

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectedUrl);
        MultiValueMap<String, String> queryParams = builder.build(true).getQueryParams();
        assertThat(queryParams).isNotNull();

        // code
        assertThat(queryParams.get(OAuth2ParameterNames.CODE)).isNotNull().isNotEmpty();
        String code = queryParams.get(OAuth2ParameterNames.CODE).get(0);
        assertThat(code).isNotBlank();

        // make a token request
        params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        params.add(OAuth2ParameterNames.CODE, code);

        req =
            MockMvcRequestBuilders
                .post(TOKEN_URL)
                .with(httpBasic(clientId, clientSecret))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .params(params);

        res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a valid json in response
        assertThat(res.getResponse().getContentAsString()).isNotBlank();

        Map<String, Serializable> response = mapper.readValue(res.getResponse().getContentAsString(), typeRef);
        assertThat(response).isNotEmpty();

        // type bearer
        assertThat(response.get(OAuth2ParameterNames.TOKEN_TYPE)).isNotNull().isInstanceOf(String.class);
        assertThat(response.get(OAuth2ParameterNames.TOKEN_TYPE)).isEqualTo("bearer");

        // access token
        assertThat(response.get(OAuth2ParameterNames.ACCESS_TOKEN)).isNotNull().isInstanceOf(String.class);
        String accessToken = (String) response.get(OAuth2ParameterNames.ACCESS_TOKEN);
        assertThat(accessToken).isNotBlank();

        // scopes are set and match request
        assertThat(response.get(OAuth2ParameterNames.SCOPE)).isNotNull().isInstanceOf(String.class);
        String scope = (String) response.get(OAuth2ParameterNames.SCOPE);
        assertThat(scope).isEqualTo(Config.SCOPE_PROFILE);
    }

    @Test
    @WithMockUserAuthentication(username = "test", realm = "test")
    public void userAuthWithOfflineScopeAndHttpBasicAuthCodeTest() throws Exception {
        // authorize request
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.RESPONSE_TYPE, ResponseType.CODE.toString());
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        // set offline_access to request refresh token in response
        params.add(OAuth2ParameterNames.SCOPE, Config.SCOPE_OFFLINE_ACCESS);

        MockHttpServletRequestBuilder req = MockMvcRequestBuilders
            .get(AUTHORIZE_URL)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .params(params);

        MvcResult res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a forward in response
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String forwardedUrl = res.getResponse().getForwardedUrl();
        assertThat(res.getResponse().getForwardedUrl()).isNotNull().startsWith(AUTHORIZED_URL);

        // keep the same session for the whole request flow
        MockHttpSession session = (MockHttpSession) res.getRequest().getSession();
        assertThat(session).isNotNull();

        // follow forward to fetch response
        req = MockMvcRequestBuilders.get(forwardedUrl).session(session);

        res = this.mockMvc.perform(req).andExpect(status().is3xxRedirection()).andReturn();

        // expect a redirect in response with query
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String redirectedUrl = res.getResponse().getRedirectedUrl();
        assertThat(redirectedUrl).isNotNull();

        // parse as queryString
        assertDoesNotThrow(() -> {
            UriComponentsBuilder.fromUriString(redirectedUrl);
        });

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectedUrl);
        MultiValueMap<String, String> queryParams = builder.build(true).getQueryParams();
        assertThat(queryParams).isNotNull();

        // code
        assertThat(queryParams.get(OAuth2ParameterNames.CODE)).isNotNull().isNotEmpty();
        String code = queryParams.get(OAuth2ParameterNames.CODE).get(0);
        assertThat(code).isNotBlank();

        // make a token request
        params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        params.add(OAuth2ParameterNames.CODE, code);

        req =
            MockMvcRequestBuilders
                .post(TOKEN_URL)
                .with(httpBasic(clientId, clientSecret))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .params(params);

        res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a valid json in response
        assertThat(res.getResponse().getContentAsString()).isNotBlank();

        Map<String, Serializable> response = mapper.readValue(res.getResponse().getContentAsString(), typeRef);
        assertThat(response).isNotEmpty();

        // type bearer
        assertThat(response.get(OAuth2ParameterNames.TOKEN_TYPE)).isNotNull().isInstanceOf(String.class);
        assertThat(response.get(OAuth2ParameterNames.TOKEN_TYPE)).isEqualTo("bearer");

        // access token
        assertThat(response.get(OAuth2ParameterNames.ACCESS_TOKEN)).isNotNull().isInstanceOf(String.class);
        String accessToken = (String) response.get(OAuth2ParameterNames.ACCESS_TOKEN);
        assertThat(accessToken).isNotBlank();

        // scopes are set and match request
        assertThat(response.get(OAuth2ParameterNames.SCOPE)).isNotNull().isInstanceOf(String.class);
        String scope = (String) response.get(OAuth2ParameterNames.SCOPE);
        assertThat(scope).isEqualTo(Config.SCOPE_OFFLINE_ACCESS);

        // refresh token is available
        assertThat(response.get(OAuth2ParameterNames.REFRESH_TOKEN)).isNotNull().isInstanceOf(String.class);
        String refreshToken = (String) response.get(OAuth2ParameterNames.REFRESH_TOKEN);
        assertThat(refreshToken).isNotBlank();
    }

    @Test
    @WithMockUserAuthentication(username = "test", realm = "test")
    public void userAuthWithValidStateAndHttpBasicAuthCodeTest() throws Exception {
        String state = "stateWithValidChars!@$().+,/-_";

        // authorize request
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.RESPONSE_TYPE, ResponseType.CODE.toString());
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        params.add(OAuth2ParameterNames.SCOPE, "");
        params.add(OAuth2ParameterNames.STATE, state);

        MockHttpServletRequestBuilder req = MockMvcRequestBuilders
            .get(AUTHORIZE_URL)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .params(params);

        MvcResult res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a forward in response
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String forwardedUrl = res.getResponse().getForwardedUrl();
        assertThat(res.getResponse().getForwardedUrl()).isNotNull().startsWith(AUTHORIZED_URL);

        // keep the same session for the whole request flow
        MockHttpSession session = (MockHttpSession) res.getRequest().getSession();
        assertThat(session).isNotNull();

        // follow forward to fetch response
        req = MockMvcRequestBuilders.get(forwardedUrl).session(session);

        res = this.mockMvc.perform(req).andExpect(status().is3xxRedirection()).andReturn();

        // expect a redirect in response with query
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String redirectedUrl = res.getResponse().getRedirectedUrl();
        assertThat(redirectedUrl).isNotNull();

        // parse as queryString
        assertDoesNotThrow(() -> {
            UriComponentsBuilder.fromUriString(redirectedUrl);
        });

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectedUrl);
        MultiValueMap<String, String> queryParams = builder.build(true).getQueryParams();
        assertThat(queryParams).isNotNull();

        // code
        assertThat(queryParams.get(OAuth2ParameterNames.CODE)).isNotNull().isNotEmpty();
        String code = queryParams.get(OAuth2ParameterNames.CODE).get(0);
        assertThat(code).isNotBlank();

        // state matches request
        assertThat(queryParams.get(OAuth2ParameterNames.STATE)).isNotNull().isNotEmpty();
        assertThat(queryParams.get(OAuth2ParameterNames.STATE).get(0)).isNotBlank().isEqualTo(state);

        // make a token request
        params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        params.add(OAuth2ParameterNames.CODE, code);

        req =
            MockMvcRequestBuilders
                .post(TOKEN_URL)
                .with(httpBasic(clientId, clientSecret))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .params(params);

        res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a valid json in response
        assertThat(res.getResponse().getContentAsString()).isNotBlank();

        Map<String, Serializable> response = mapper.readValue(res.getResponse().getContentAsString(), typeRef);
        assertThat(response).isNotEmpty();

        // type bearer
        assertThat(response.get(OAuth2ParameterNames.TOKEN_TYPE)).isNotNull().isInstanceOf(String.class);
        assertThat(response.get(OAuth2ParameterNames.TOKEN_TYPE)).isEqualTo("bearer");

        // access token
        assertThat(response.get(OAuth2ParameterNames.ACCESS_TOKEN)).isNotNull().isInstanceOf(String.class);
        String accessToken = (String) response.get(OAuth2ParameterNames.ACCESS_TOKEN);
        assertThat(accessToken).isNotBlank();

        // scopes are set and match request
        assertThat(response.get(OAuth2ParameterNames.SCOPE)).isNotNull().isInstanceOf(String.class);
        String scope = (String) response.get(OAuth2ParameterNames.SCOPE);
        assertThat(scope).isEmpty();
    }

    @Test
    public void noAuthAuthCodeTest() throws Exception {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.RESPONSE_TYPE, ResponseType.CODE.toString());
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        params.add(OAuth2ParameterNames.SCOPE, "");

        MockHttpServletRequestBuilder req = MockMvcRequestBuilders
            .get(AUTHORIZE_URL)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .params(params);

        MvcResult res = this.mockMvc.perform(req).andExpect(status().is3xxRedirection()).andReturn();

        // expect a redirect in response to login
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String redirectedUrl = res.getResponse().getRedirectedUrl();
        assertThat(redirectedUrl).isNotNull();

        // parse as queryString
        assertDoesNotThrow(() -> {
            UriComponentsBuilder.fromUriString(redirectedUrl);
        });

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectedUrl);
        MultiValueMap<String, String> queryParams = builder.build(true).getQueryParams();

        // no code
        assertThat(queryParams.get(OAuth2ParameterNames.CODE))
            .satisfiesAnyOf(code -> assertThat(code).isNull(), code -> assertThat(code).isEmpty());
    }

    @Test
    @WithMockUserAuthentication(username = "test", realm = "two")
    public void userAuthWrongRealmAuthCodeTest() throws Exception {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.RESPONSE_TYPE, ResponseType.CODE.toString());
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        params.add(OAuth2ParameterNames.SCOPE, "");

        MockHttpServletRequestBuilder req = MockMvcRequestBuilders
            .get(AUTHORIZE_URL)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .params(params);

        MvcResult res = this.mockMvc.perform(req).andExpect(status().is3xxRedirection()).andReturn();

        // expect a redirect in response to login
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String redirectedUrl = res.getResponse().getRedirectedUrl();
        assertThat(redirectedUrl).isNotNull();

        // parse as queryString
        assertDoesNotThrow(() -> {
            UriComponentsBuilder.fromUriString(redirectedUrl);
        });

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectedUrl);
        MultiValueMap<String, String> queryParams = builder.build(true).getQueryParams();

        // no code
        assertThat(queryParams.get(OAuth2ParameterNames.CODE))
            .satisfiesAnyOf(code -> assertThat(code).isNull(), code -> assertThat(code).isEmpty());
    }

    @Test
    @WithMockUserAuthentication(username = "test", realm = "test")
    public void userAuthNoClientAuthCodeTest() throws Exception {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.RESPONSE_TYPE, ResponseType.CODE.toString());
        params.add(OAuth2ParameterNames.SCOPE, "");

        MockHttpServletRequestBuilder req = MockMvcRequestBuilders
            .get(AUTHORIZE_URL)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .params(params);

        MvcResult res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a forward in response to error
        assertThat(res.getResponse().getContentAsString()).isBlank();
        assertThat(res.getResponse().getForwardedUrl()).isNotNull().isEqualTo(ERROR_URL);
    }

    @Test
    @WithMockUserAuthentication(username = "test", realm = "test")
    public void userAuthWrongScopeAuthCodeTest() throws Exception {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.RESPONSE_TYPE, ResponseType.CODE.toString());
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        params.add(OAuth2ParameterNames.SCOPE, "invalid-scope");

        MockHttpServletRequestBuilder req = MockMvcRequestBuilders
            .get(AUTHORIZE_URL)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .params(params);

        MvcResult res = this.mockMvc.perform(req).andExpect(status().is3xxRedirection()).andReturn();

        // expect a redirect in response with error
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String redirectedUrl = res.getResponse().getRedirectedUrl();
        assertThat(redirectedUrl).isNotNull();

        // parse as queryString
        assertDoesNotThrow(() -> {
            UriComponentsBuilder.fromUriString(redirectedUrl);
        });

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectedUrl);
        MultiValueMap<String, String> response = builder.build(true).getQueryParams();

        // error
        assertThat(response.get(OAuth2ParameterNames.ERROR)).isNotNull().isNotEmpty();
        assertThat(response.get(OAuth2ParameterNames.ERROR).get(0)).isEqualTo("invalid_scope");

        // no code
        assertThat(response.get(OAuth2ParameterNames.CODE))
            .satisfiesAnyOf(code -> assertThat(code).isNull(), code -> assertThat(code).isEmpty());
    }

    @Test
    @WithMockUserAuthentication(username = "test", realm = "test")
    public void userAuthWrongRedirectAuthCodeTest() throws Exception {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.RESPONSE_TYPE, ResponseType.CODE.toString());
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        params.add(OAuth2ParameterNames.SCOPE, "");
        params.add(OAuth2ParameterNames.REDIRECT_URI, "http123");

        MockHttpServletRequestBuilder req = MockMvcRequestBuilders
            .get(AUTHORIZE_URL)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .params(params);

        MvcResult res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a forward in response to error
        assertThat(res.getResponse().getContentAsString()).isBlank();
        assertThat(res.getResponse().getForwardedUrl()).isNotNull().isEqualTo(ERROR_URL);
    }

    @Test
    @WithMockUserAuthentication(username = "test", realm = "test")
    public void userAuthInvalidStateAuthCodeTest() throws Exception {
        // token request
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.RESPONSE_TYPE, ResponseType.CODE.toString());
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        params.add(OAuth2ParameterNames.SCOPE, "");
        params.add(OAuth2ParameterNames.STATE, "stateWithInvalidChars#\\");

        MockHttpServletRequestBuilder req = MockMvcRequestBuilders
            .get(AUTHORIZE_URL)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .params(params);

        MvcResult res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a forward in response to error
        assertThat(res.getResponse().getContentAsString()).isBlank();
        assertThat(res.getResponse().getForwardedUrl()).isNotNull().isEqualTo(ERROR_URL);
    }

    @Test
    @WithMockUserAuthentication(username = "test", realm = "test")
    public void userAuthWithInvalidHttpBasicAuthCodeTest() throws Exception {
        // authorize request
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.RESPONSE_TYPE, ResponseType.CODE.toString());
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        // set empty scopes to avoid fall back to predefined
        params.add(OAuth2ParameterNames.SCOPE, "");

        MockHttpServletRequestBuilder req = MockMvcRequestBuilders
            .get(AUTHORIZE_URL)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .params(params);

        MvcResult res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a forward in response
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String forwardedUrl = res.getResponse().getForwardedUrl();
        assertThat(res.getResponse().getForwardedUrl()).isNotNull().startsWith(AUTHORIZED_URL);

        // keep the same session for the whole request flow
        MockHttpSession session = (MockHttpSession) res.getRequest().getSession();
        assertThat(session).isNotNull();

        // follow forward to fetch response
        req = MockMvcRequestBuilders.get(forwardedUrl).session(session);

        res = this.mockMvc.perform(req).andExpect(status().is3xxRedirection()).andReturn();

        // expect a redirect in response with query
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String redirectedUrl = res.getResponse().getRedirectedUrl();
        assertThat(redirectedUrl).isNotNull();

        // parse as queryString
        assertDoesNotThrow(() -> {
            UriComponentsBuilder.fromUriString(redirectedUrl);
        });

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectedUrl);
        MultiValueMap<String, String> queryParams = builder.build(true).getQueryParams();
        assertThat(queryParams).isNotNull();

        // code
        assertThat(queryParams.get(OAuth2ParameterNames.CODE)).isNotNull().isNotEmpty();
        String code = queryParams.get(OAuth2ParameterNames.CODE).get(0);
        assertThat(code).isNotBlank();

        // make a token request
        params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        params.add(OAuth2ParameterNames.CODE, code);

        req =
            MockMvcRequestBuilders
                .post(TOKEN_URL)
                .with(httpBasic(clientId, "secret"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .params(params);

        res = this.mockMvc.perform(req).andExpect(status().isUnauthorized()).andReturn();

        // expect a 401 with an error
        assertThat(res.getResponse().getContentAsString()).isNotBlank();

        Map<String, Serializable> response = mapper.readValue(res.getResponse().getContentAsString(), typeRef);
        assertThat(response).isNotEmpty();
        assertThat(response.get("error")).isEqualTo("unauthorized");
    }

    @Test
    @WithMockUserAuthentication(username = "test", realm = "test")
    public void userAuthWithWrongCodeAndHttpBasicAuthCodeTest() throws Exception {
        // authorize request
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.RESPONSE_TYPE, ResponseType.CODE.toString());
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        // set empty scopes to avoid fall back to predefined
        params.add(OAuth2ParameterNames.SCOPE, "");

        MockHttpServletRequestBuilder req = MockMvcRequestBuilders
            .get(AUTHORIZE_URL)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .params(params);

        MvcResult res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a forward in response
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String forwardedUrl = res.getResponse().getForwardedUrl();
        assertThat(res.getResponse().getForwardedUrl()).isNotNull().startsWith(AUTHORIZED_URL);

        // keep the same session for the whole request flow
        MockHttpSession session = (MockHttpSession) res.getRequest().getSession();
        assertThat(session).isNotNull();

        // follow forward to fetch response
        req = MockMvcRequestBuilders.get(forwardedUrl).session(session);

        res = this.mockMvc.perform(req).andExpect(status().is3xxRedirection()).andReturn();

        // expect a redirect in response with query
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String redirectedUrl = res.getResponse().getRedirectedUrl();
        assertThat(redirectedUrl).isNotNull();

        // parse as queryString
        assertDoesNotThrow(() -> {
            UriComponentsBuilder.fromUriString(redirectedUrl);
        });

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectedUrl);
        MultiValueMap<String, String> queryParams = builder.build(true).getQueryParams();
        assertThat(queryParams).isNotNull();

        // code
        assertThat(queryParams.get(OAuth2ParameterNames.CODE)).isNotNull().isNotEmpty();
        assertThat(queryParams.get(OAuth2ParameterNames.CODE).get(0)).isNotBlank();

        // make a token request
        params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        params.add(OAuth2ParameterNames.CODE, "code");

        req =
            MockMvcRequestBuilders
                .post(TOKEN_URL)
                .with(httpBasic(clientId, clientSecret))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .params(params);

        res = this.mockMvc.perform(req).andExpect(status().isBadRequest()).andReturn();

        // expect an error in response
        assertThat(res.getResponse().getContentAsString()).isNotBlank();

        Map<String, Serializable> response = mapper.readValue(res.getResponse().getContentAsString(), typeRef);
        assertThat(response).isNotEmpty();
        assertThat(response.get("error")).isEqualTo("invalid_grant");

        // there is no access token
        assertThat(response.get(OAuth2ParameterNames.ACCESS_TOKEN)).isNull();
    }

    @Test
    @WithMockUserAuthentication(username = "test", realm = "test")
    public void userAuthWithRedirectMismatchAndHttpBasicAuthCodeTest() throws Exception {
        // authorize request
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.RESPONSE_TYPE, ResponseType.CODE.toString());
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        params.add(OAuth2ParameterNames.SCOPE, "");

        MockHttpServletRequestBuilder req = MockMvcRequestBuilders
            .get(AUTHORIZE_URL)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .params(params);

        MvcResult res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a forward in response
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String forwardedUrl = res.getResponse().getForwardedUrl();
        assertThat(res.getResponse().getForwardedUrl()).isNotNull().startsWith(AUTHORIZED_URL);

        // keep the same session for the whole request flow
        MockHttpSession session = (MockHttpSession) res.getRequest().getSession();
        assertThat(session).isNotNull();

        // follow forward to fetch response
        req = MockMvcRequestBuilders.get(forwardedUrl).session(session);

        res = this.mockMvc.perform(req).andExpect(status().is3xxRedirection()).andReturn();

        // expect a redirect in response with query
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String redirectedUrl = res.getResponse().getRedirectedUrl();
        assertThat(redirectedUrl).isNotNull();

        // parse as queryString
        assertDoesNotThrow(() -> {
            UriComponentsBuilder.fromUriString(redirectedUrl);
        });

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectedUrl);
        MultiValueMap<String, String> queryParams = builder.build(true).getQueryParams();
        assertThat(queryParams).isNotNull();

        // code
        assertThat(queryParams.get(OAuth2ParameterNames.CODE)).isNotNull().isNotEmpty();
        String code = queryParams.get(OAuth2ParameterNames.CODE).get(0);
        assertThat(code).isNotBlank();

        // make a token request
        params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        params.add(OAuth2ParameterNames.CODE, code);
        // change redirect
        params.add(OAuth2ParameterNames.REDIRECT_URI, "http://localhost");

        req =
            MockMvcRequestBuilders
                .post(TOKEN_URL)
                .with(httpBasic(clientId, clientSecret))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .params(params);

        res = this.mockMvc.perform(req).andExpect(status().isBadRequest()).andReturn();

        // expect an error in response
        assertThat(res.getResponse().getContentAsString()).isNotBlank();

        Map<String, Serializable> response = mapper.readValue(res.getResponse().getContentAsString(), typeRef);
        assertThat(response).isNotEmpty();
        assertThat(response.get("error")).isEqualTo("invalid_grant");

        // there is no access token
        assertThat(response.get(OAuth2ParameterNames.ACCESS_TOKEN)).isNull();
    }

    @Test
    @WithMockUserAuthentication(username = "test", realm = "test")
    public void userAuthWithScopeMismatchAndHttpBasicAuthCodeTest() throws Exception {
        // authorize request
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.RESPONSE_TYPE, ResponseType.CODE.toString());
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        // set empty scopes
        params.add(OAuth2ParameterNames.SCOPE, "");

        MockHttpServletRequestBuilder req = MockMvcRequestBuilders
            .get(AUTHORIZE_URL)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .params(params);

        MvcResult res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a forward in response
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String forwardedUrl = res.getResponse().getForwardedUrl();
        assertThat(res.getResponse().getForwardedUrl()).isNotNull().startsWith(AUTHORIZED_URL);

        // keep the same session for the whole request flow
        MockHttpSession session = (MockHttpSession) res.getRequest().getSession();
        assertThat(session).isNotNull();

        // follow forward to fetch response
        req = MockMvcRequestBuilders.get(forwardedUrl).session(session);

        res = this.mockMvc.perform(req).andExpect(status().is3xxRedirection()).andReturn();

        // expect a redirect in response with query
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String redirectedUrl = res.getResponse().getRedirectedUrl();
        assertThat(redirectedUrl).isNotNull();

        // parse as queryString
        assertDoesNotThrow(() -> {
            UriComponentsBuilder.fromUriString(redirectedUrl);
        });

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectedUrl);
        MultiValueMap<String, String> queryParams = builder.build(true).getQueryParams();
        assertThat(queryParams).isNotNull();

        // code
        assertThat(queryParams.get(OAuth2ParameterNames.CODE)).isNotNull().isNotEmpty();
        String code = queryParams.get(OAuth2ParameterNames.CODE).get(0);
        assertThat(code).isNotBlank();

        // make a token request
        params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        params.add(OAuth2ParameterNames.CODE, code);
        // require additional scopes
        params.add(OAuth2ParameterNames.SCOPE, Config.SCOPE_PROFILE);

        req =
            MockMvcRequestBuilders
                .post(TOKEN_URL)
                .with(httpBasic(clientId, clientSecret))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .params(params);

        res = this.mockMvc.perform(req).andExpect(status().isBadRequest()).andReturn();

        // expect an error in response
        assertThat(res.getResponse().getContentAsString()).isNotBlank();

        Map<String, Serializable> response = mapper.readValue(res.getResponse().getContentAsString(), typeRef);
        assertThat(response).isNotEmpty();
        assertThat(response.get("error")).isEqualTo("invalid_scope");

        // there is no access token
        assertThat(response.get(OAuth2ParameterNames.ACCESS_TOKEN)).isNull();
    }

    @Test
    @WithMockUserAuthentication(username = "test", realm = "test")
    public void userAuthWithScopeMismatchForRefreshAndHttpBasicAuthCodeTest() throws Exception {
        // authorize request
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.RESPONSE_TYPE, ResponseType.CODE.toString());
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        // set empty scopes
        params.add(OAuth2ParameterNames.SCOPE, "");

        MockHttpServletRequestBuilder req = MockMvcRequestBuilders
            .get(AUTHORIZE_URL)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .params(params);

        MvcResult res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a forward in response
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String forwardedUrl = res.getResponse().getForwardedUrl();
        assertThat(res.getResponse().getForwardedUrl()).isNotNull().startsWith(AUTHORIZED_URL);

        // keep the same session for the whole request flow
        MockHttpSession session = (MockHttpSession) res.getRequest().getSession();
        assertThat(session).isNotNull();

        // follow forward to fetch response
        req = MockMvcRequestBuilders.get(forwardedUrl).session(session);

        res = this.mockMvc.perform(req).andExpect(status().is3xxRedirection()).andReturn();

        // expect a redirect in response with query
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String redirectedUrl = res.getResponse().getRedirectedUrl();
        assertThat(redirectedUrl).isNotNull();

        // parse as queryString
        assertDoesNotThrow(() -> {
            UriComponentsBuilder.fromUriString(redirectedUrl);
        });

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectedUrl);
        MultiValueMap<String, String> queryParams = builder.build(true).getQueryParams();
        assertThat(queryParams).isNotNull();

        // code
        assertThat(queryParams.get(OAuth2ParameterNames.CODE)).isNotNull().isNotEmpty();
        String code = queryParams.get(OAuth2ParameterNames.CODE).get(0);
        assertThat(code).isNotBlank();

        // make a token request
        params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        params.add(OAuth2ParameterNames.CODE, code);
        // require additional scopes for refresh token
        params.add(OAuth2ParameterNames.SCOPE, Config.SCOPE_OFFLINE_ACCESS);

        req =
            MockMvcRequestBuilders
                .post(TOKEN_URL)
                .with(httpBasic(clientId, clientSecret))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .params(params);

        res = this.mockMvc.perform(req).andExpect(status().isBadRequest()).andReturn();

        // expect an error in response
        assertThat(res.getResponse().getContentAsString()).isNotBlank();

        Map<String, Serializable> response = mapper.readValue(res.getResponse().getContentAsString(), typeRef);
        assertThat(response).isNotEmpty();
        assertThat(response.get("error")).isEqualTo("invalid_scope");

        // there is no access token
        assertThat(response.get(OAuth2ParameterNames.ACCESS_TOKEN)).isNull();

        // there is no refresh token
        assertThat(response.get(OAuth2ParameterNames.REFRESH_TOKEN)).isNull();
    }

    @Test
    @WithMockUserAuthentication(username = "test", realm = "test")
    public void userAuthWithClientMismatchAndHttpBasicAuthCodeTest() throws Exception {
        // authorize request
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.RESPONSE_TYPE, ResponseType.CODE.toString());
        // swap client later on auth
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        // set empty scopes
        params.add(OAuth2ParameterNames.SCOPE, "");

        MockHttpServletRequestBuilder req = MockMvcRequestBuilders
            .get(AUTHORIZE_URL)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .params(params);

        MvcResult res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a forward in response
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String forwardedUrl = res.getResponse().getForwardedUrl();
        assertThat(res.getResponse().getForwardedUrl()).isNotNull().startsWith(AUTHORIZED_URL);

        // keep the same session for the whole request flow
        MockHttpSession session = (MockHttpSession) res.getRequest().getSession();
        assertThat(session).isNotNull();

        // follow forward to fetch response
        req = MockMvcRequestBuilders.get(forwardedUrl).session(session);

        res = this.mockMvc.perform(req).andExpect(status().is3xxRedirection()).andReturn();

        // expect a redirect in response with query
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String redirectedUrl = res.getResponse().getRedirectedUrl();
        assertThat(redirectedUrl).isNotNull();

        // parse as queryString
        assertDoesNotThrow(() -> {
            UriComponentsBuilder.fromUriString(redirectedUrl);
        });

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectedUrl);
        MultiValueMap<String, String> queryParams = builder.build(true).getQueryParams();
        assertThat(queryParams).isNotNull();

        // code
        assertThat(queryParams.get(OAuth2ParameterNames.CODE)).isNotNull().isNotEmpty();
        String code = queryParams.get(OAuth2ParameterNames.CODE).get(0);
        assertThat(code).isNotBlank();

        // make a token request
        params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        params.add(OAuth2ParameterNames.CODE, code);

        req =
            MockMvcRequestBuilders
                .post(TOKEN_URL)
                .with(httpBasic(client2Id, client2Secret))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .params(params);

        res = this.mockMvc.perform(req).andExpect(status().is4xxClientError()).andReturn();

        // expect an error in response
        assertThat(res.getResponse().getContentAsString()).isNotBlank();

        Map<String, Serializable> response = mapper.readValue(res.getResponse().getContentAsString(), typeRef);
        assertThat(response).isNotEmpty();
        assertThat(response.get("error")).isEqualTo("invalid_client");

        // there is no access token
        assertThat(response.get(OAuth2ParameterNames.ACCESS_TOKEN)).isNull();
    }

    @Test
    @WithMockUserAuthentication(username = "test", realm = "test")
    public void userAuthWithFormPostResponseModeAndIssuerTest() throws Exception {
        // fetch issuer from metadata
        MockHttpServletRequestBuilder metaReq = MockMvcRequestBuilders
            .get("/.well-known/oauth-authorization-server")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED);

        MvcResult metaRes = this.mockMvc.perform(metaReq).andExpect(status().isOk()).andReturn();
        String metaJson = metaRes.getResponse().getContentAsString();
        Map<String, Serializable> metadata = mapper.readValue(metaJson, typeRef);

        assertThat(metadata.get("issuer")).isNotNull().isInstanceOf(String.class);
        String expectedIssuer = (String) metadata.get("issuer");
        assertThat(expectedIssuer).isNotBlank();

        // authorize request
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.RESPONSE_TYPE, ResponseType.CODE.toString());
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        params.add(OAuth2ParameterNames.SCOPE, "");
        params.add("response_mode", "form_post");

        MockHttpServletRequestBuilder req = MockMvcRequestBuilders
            .get(AUTHORIZE_URL)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .params(params);

        MvcResult res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect a forward in response
        assertThat(res.getResponse().getContentAsString()).isBlank();

        String forwardedUrl = res.getResponse().getForwardedUrl();
        assertThat(forwardedUrl).isNotNull().startsWith("/oauth/authorized_post");

        // keep same session for whole request flow
        MockHttpSession session = (MockHttpSession) res.getRequest().getSession();
        assertThat(session).isNotNull();

        // follow forward to fetch response
        req = MockMvcRequestBuilders.get(forwardedUrl).session(session);
        res = this.mockMvc.perform(req).andExpect(status().isOk()).andReturn();

        // expect HTML form response
        String htmlContent = res.getResponse().getContentAsString();
        assertThat(htmlContent).isNotBlank();

        // parse HTML form to extract parameters and validate compliance
        Document doc = Jsoup.parse(htmlContent);
        Element form = doc.select("form").first();
        assertThat(form).isNotNull();

        // verify form has POST method and correct action
        assertThat(form.attr("method")).isEqualToIgnoringCase("post");
        String formAction = form.attr("action");
        assertThat(formAction).isEqualTo("http://localhost:9999");

        // verify body has onload auto-submit as per OAuth2 form_post spec
        Element body = doc.select("body").first();
        assertThat(body).isNotNull();
        assertThat(body.attr("onload")).contains("document.forms[0].submit()");

        // verify noscript fallback for accessibility (check the one inside form)
        Elements noscriptElements = doc.select("form noscript");
        assertThat(noscriptElements).isNotEmpty();
        Element formNoscript = noscriptElements.first();
        Element submitButton = formNoscript.select("input[type=submit]").first();
        assertThat(submitButton).isNotNull();

        // extract hidden fields from form
        Elements hiddenInputs = form.select("input[type=\"hidden\"]");
        assertThat(hiddenInputs).isNotEmpty();

        MultiValueMap<String, String> formParams = new LinkedMultiValueMap<>();
        for (Element input : hiddenInputs) {
            String name = input.attr("name");
            String value = input.attr("value");
            if (StringUtils.hasText(name) && StringUtils.hasText(value)) {
                formParams.add(name, value);
            }
        }

        // verify iss parameter is present in form
        assertThat(formParams.get("iss")).isNotNull().isNotEmpty();
        String formIssuer = formParams.get("iss").get(0);
        assertThat(formIssuer).isEqualTo(expectedIssuer);

        // setup mock client server to receive the POST
        mockClientServer.stubFor(WireMock.post(WireMock.urlEqualTo("/"))
            .willReturn(WireMock.aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "text/plain")
                .withBody("POST received")));

        // simulate client POST to mock server (using random port)
        // Form action should still be http://localhost:9999 as per client config
        String clientRedirectUri = mockClientServer.baseUrl();

        // Build form data as URL-encoded string
        StringBuilder formData = new StringBuilder();
        for (Map.Entry<String, List<String>> entry : formParams.entrySet()) {
            if (formData.length() > 0) {
                formData.append("&");
            }
            formData.append(entry.getKey()).append("=").append(entry.getValue().get(0));
        }

        // Make actual HTTP POST to mock client server
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(clientRedirectUri))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(formData.toString()))
            .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        // verify POST response
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo("POST received");

        // verify that our mock server received the POST with correct parameters
        mockClientServer.verify(WireMock.postRequestedFor(WireMock.urlEqualTo("/"))
            .withRequestBody(WireMock.containing("code=" + formParams.get("code").get(0)))
            .withRequestBody(WireMock.containing("iss=" + expectedIssuer)));
    }

    private static final String AUTHORIZE_URL = AuthorizationEndpoint.AUTHORIZATION_URL;
    private static final String AUTHORIZED_URL = AuthorizationEndpoint.AUTHORIZED_URL;
    private static final String TOKEN_URL = TokenEndpoint.TOKEN_URL;
    private static final String ERROR_URL = ErrorEndpoint.ERROR_URL;

    private final TypeReference<Map<String, Serializable>> typeRef = new TypeReference<Map<String, Serializable>>() {};
}
