/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com)
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.tokenprocessor;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dao.TokenManagementDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenExtendedAttributes;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.AccessTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.longThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;

/**
 * Unit tests for DefaultRefreshTokenGrantProcessor.
 */
@WithCarbonHome
public class DefaultRefreshTokenGrantProcessorTest {

    private static final String TEST_CONSUMER_KEY = "test_consumer_key";
    private static final String TEST_REFRESH_TOKEN = "test_refresh_token";
    private static final String TEST_ACCESS_TOKEN = "test_access_token";
    private static final String TEST_TOKEN_ID = "test_token_id";
    private static final String TEST_GRANT_TYPE = "authorization_code";
    private static final String TEST_USER_STORE_DOMAIN = "PRIMARY";
    private static final String TEST_TENANT_DOMAIN = "carbon.super";
    private static final String[] TEST_SCOPE = new String[]{"openid", "profile"};
    private static final String REUSE_COUNT_KEY =
            OAuthConstants.GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT;

    private DefaultRefreshTokenGrantProcessor processor;
    private AutoCloseable closeable;

    @Mock
    private OAuthTokenPersistenceFactory mockPersistenceFactory;

    @Mock
    private TokenManagementDAO mockTokenManagementDAO;

    @Mock
    private AccessTokenDAO mockAccessTokenDAO;

    @Mock
    private OAuthServerConfiguration mockOAuthServerConfiguration;

    @Mock
    private AuthorizationGrantCache mockAuthorizationGrantCache;

    private MockedStatic<OAuthTokenPersistenceFactory> persistenceFactoryMock;
    private MockedStatic<OAuthServerConfiguration> oAuthServerConfigMock;
    private MockedStatic<OAuth2Util> oAuth2UtilMock;
    private MockedStatic<AuthorizationGrantCache> authorizationGrantCacheMock;

    @BeforeMethod
    public void setUp() throws Exception {

        closeable = MockitoAnnotations.openMocks(this);

        persistenceFactoryMock = mockStatic(OAuthTokenPersistenceFactory.class);
        oAuthServerConfigMock = mockStatic(OAuthServerConfiguration.class);
        oAuth2UtilMock = mockStatic(OAuth2Util.class);
        authorizationGrantCacheMock = mockStatic(AuthorizationGrantCache.class);

        persistenceFactoryMock.when(OAuthTokenPersistenceFactory::getInstance).thenReturn(mockPersistenceFactory);
        oAuthServerConfigMock.when(OAuthServerConfiguration::getInstance).thenReturn(mockOAuthServerConfiguration);
        authorizationGrantCacheMock.when(AuthorizationGrantCache::getInstance).thenReturn(mockAuthorizationGrantCache);

        lenient().when(mockPersistenceFactory.getTokenManagementDAO()).thenReturn(mockTokenManagementDAO);
        lenient().when(mockPersistenceFactory.getAccessTokenDAOImpl(anyString())).thenReturn(mockAccessTokenDAO);

        oAuth2UtilMock.when(() -> OAuth2Util.buildScopeString(any(String[].class))).thenReturn("openid profile");

        processor = new DefaultRefreshTokenGrantProcessor();
    }

    @AfterMethod
    public void tearDown() throws Exception {

        closeMockSafely(persistenceFactoryMock);
        closeMockSafely(oAuthServerConfigMock);
        closeMockSafely(oAuth2UtilMock);
        closeMockSafely(authorizationGrantCacheMock);
        if (closeable != null) {
            closeable.close();
        }
    }

    // ===================== validateRefreshTokenReuseLimit tests =====================

    @Test
    public void testValidateRefreshToken_GracefulRotationDisabled_ShouldPass() throws Exception {

        OAuthAppDO appDO = createAppDO(false, 5);
        oAuth2UtilMock.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CONSUMER_KEY, TEST_TENANT_DOMAIN))
                .thenReturn(appDO);
        RefreshTokenValidationDataDO validationBean = createValidationBean();
        validationBean.setAccessToken(TEST_ACCESS_TOKEN);
        when(mockTokenManagementDAO.validateRefreshToken(TEST_CONSUMER_KEY, TEST_REFRESH_TOKEN))
                .thenReturn(validationBean);

        OAuthTokenReqMessageContext ctx = createTokenReqCtx(TEST_TENANT_DOMAIN);
        RefreshTokenValidationDataDO result = processor.validateRefreshToken(ctx);

        assertNotNull(result);
    }

    @Test
    public void testValidateRefreshToken_NoExtendedAttributes_ShouldPass() throws Exception {

        OAuthAppDO appDO = createAppDO(true, 5);
        oAuth2UtilMock.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CONSUMER_KEY, TEST_TENANT_DOMAIN))
                .thenReturn(appDO);
        RefreshTokenValidationDataDO validationBean = createValidationBean();
        validationBean.setAccessToken(TEST_ACCESS_TOKEN);
        validationBean.setAccessTokenExtendedAttributes(null);
        when(mockTokenManagementDAO.validateRefreshToken(TEST_CONSUMER_KEY, TEST_REFRESH_TOKEN))
                .thenReturn(validationBean);

        OAuthTokenReqMessageContext ctx = createTokenReqCtx(TEST_TENANT_DOMAIN);
        RefreshTokenValidationDataDO result = processor.validateRefreshToken(ctx);

        assertNotNull(result);
    }

    @Test
    public void testValidateRefreshToken_AttributesPresentButNoReuseCountKey_ShouldPass() throws Exception {

        OAuthAppDO appDO = createAppDO(true, 5);
        oAuth2UtilMock.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CONSUMER_KEY, TEST_TENANT_DOMAIN))
                .thenReturn(appDO);
        RefreshTokenValidationDataDO validationBean = createValidationBean();
        validationBean.setAccessToken(TEST_ACCESS_TOKEN);
        Map<String, String> params = new HashMap<>();
        params.put("someOtherKey", "someValue");
        validationBean.setAccessTokenExtendedAttributes(new AccessTokenExtendedAttributes(params));
        when(mockTokenManagementDAO.validateRefreshToken(TEST_CONSUMER_KEY, TEST_REFRESH_TOKEN))
                .thenReturn(validationBean);

        OAuthTokenReqMessageContext ctx = createTokenReqCtx(TEST_TENANT_DOMAIN);
        RefreshTokenValidationDataDO result = processor.validateRefreshToken(ctx);

        assertNotNull(result);
    }

    @Test
    public void testValidateRefreshToken_UnparseableReuseCount_ShouldPass() throws Exception {

        OAuthAppDO appDO = createAppDO(true, 5);
        oAuth2UtilMock.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CONSUMER_KEY, TEST_TENANT_DOMAIN))
                .thenReturn(appDO);
        RefreshTokenValidationDataDO validationBean = createValidationBean();
        validationBean.setAccessToken(TEST_ACCESS_TOKEN);
        validationBean.setAccessTokenExtendedAttributes(new AccessTokenExtendedAttributes(
                Collections.singletonMap(REUSE_COUNT_KEY, "not-a-number")));
        when(mockTokenManagementDAO.validateRefreshToken(TEST_CONSUMER_KEY, TEST_REFRESH_TOKEN))
                .thenReturn(validationBean);

        OAuthTokenReqMessageContext ctx = createTokenReqCtx(TEST_TENANT_DOMAIN);
        RefreshTokenValidationDataDO result = processor.validateRefreshToken(ctx);

        assertNotNull(result);
    }

    @Test
    public void testValidateRefreshToken_ReuseCountBelowLimit_ShouldPass() throws Exception {

        OAuthAppDO appDO = createAppDO(true, 5);
        oAuth2UtilMock.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CONSUMER_KEY, TEST_TENANT_DOMAIN))
                .thenReturn(appDO);
        RefreshTokenValidationDataDO validationBean = createValidationBean();
        validationBean.setAccessToken(TEST_ACCESS_TOKEN);
        validationBean.setAccessTokenExtendedAttributes(new AccessTokenExtendedAttributes(
                Collections.singletonMap(REUSE_COUNT_KEY, "4")));
        when(mockTokenManagementDAO.validateRefreshToken(TEST_CONSUMER_KEY, TEST_REFRESH_TOKEN))
                .thenReturn(validationBean);

        OAuthTokenReqMessageContext ctx = createTokenReqCtx(TEST_TENANT_DOMAIN);
        RefreshTokenValidationDataDO result = processor.validateRefreshToken(ctx);

        assertNotNull(result);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class,
            expectedExceptionsMessageRegExp = ".*graceful reuse limit.*")
    public void testValidateRefreshToken_ReuseCountEqualsLimit_ShouldThrow() throws Exception {

        OAuthAppDO appDO = createAppDO(true, 5);
        oAuth2UtilMock.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CONSUMER_KEY, TEST_TENANT_DOMAIN))
                .thenReturn(appDO);
        RefreshTokenValidationDataDO validationBean = createValidationBean();
        validationBean.setAccessToken(TEST_ACCESS_TOKEN);
        validationBean.setAccessTokenExtendedAttributes(new AccessTokenExtendedAttributes(
                Collections.singletonMap(REUSE_COUNT_KEY, "5")));
        when(mockTokenManagementDAO.validateRefreshToken(TEST_CONSUMER_KEY, TEST_REFRESH_TOKEN))
                .thenReturn(validationBean);

        processor.validateRefreshToken(createTokenReqCtx(TEST_TENANT_DOMAIN));
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class,
            expectedExceptionsMessageRegExp = ".*graceful reuse limit.*")
    public void testValidateRefreshToken_ReuseCountAboveLimit_ShouldThrow() throws Exception {

        OAuthAppDO appDO = createAppDO(true, 5);
        oAuth2UtilMock.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CONSUMER_KEY, TEST_TENANT_DOMAIN))
                .thenReturn(appDO);
        RefreshTokenValidationDataDO validationBean = createValidationBean();
        validationBean.setAccessToken(TEST_ACCESS_TOKEN);
        validationBean.setAccessTokenExtendedAttributes(new AccessTokenExtendedAttributes(
                Collections.singletonMap(REUSE_COUNT_KEY, "7")));
        when(mockTokenManagementDAO.validateRefreshToken(TEST_CONSUMER_KEY, TEST_REFRESH_TOKEN))
                .thenReturn(validationBean);

        processor.validateRefreshToken(createTokenReqCtx(TEST_TENANT_DOMAIN));
    }

    @Test
    public void testValidateRefreshToken_BlankTenantDomain_FallsBackToClientIdOnly() throws Exception {

        OAuthAppDO appDO = createAppDO(false, 5);
        oAuth2UtilMock.when(() -> OAuth2Util.getAppInformationByClientIdOnly(TEST_CONSUMER_KEY))
                .thenReturn(appDO);
        RefreshTokenValidationDataDO validationBean = createValidationBean();
        validationBean.setAccessToken(TEST_ACCESS_TOKEN);
        when(mockTokenManagementDAO.validateRefreshToken(TEST_CONSUMER_KEY, TEST_REFRESH_TOKEN))
                .thenReturn(validationBean);

        OAuthTokenReqMessageContext ctx = createTokenReqCtx("");
        processor.validateRefreshToken(ctx);

        oAuth2UtilMock.verify(() -> OAuth2Util.getAppInformationByClientIdOnly(TEST_CONSUMER_KEY));
        oAuth2UtilMock.verify(() -> OAuth2Util.getAppInformationByClientId(anyString(), anyString()), never());
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testValidateRefreshToken_InvalidOAuthClientException_ShouldWrap() throws Exception {

        oAuth2UtilMock.when(() -> OAuth2Util.getAppInformationByClientId(TEST_CONSUMER_KEY, TEST_TENANT_DOMAIN))
                .thenThrow(new InvalidOAuthClientException("not found"));
        RefreshTokenValidationDataDO validationBean = createValidationBean();
        validationBean.setAccessToken(TEST_ACCESS_TOKEN);
        when(mockTokenManagementDAO.validateRefreshToken(TEST_CONSUMER_KEY, TEST_REFRESH_TOKEN))
                .thenReturn(validationBean);

        processor.validateRefreshToken(createTokenReqCtx(TEST_TENANT_DOMAIN));
    }

    // ===================== persistNewToken – graceful rotation branch =====================

    @Test
    @SuppressWarnings("unchecked")
    public void testPersistNewToken_GracefulRotation_NoSiblings_StampsOriginalValidity() throws Exception {

        RefreshTokenValidationDataDO oldToken = createValidationBean();
        oldToken.setIssuedTime(new Timestamp(System.currentTimeMillis() - 60_000));

        OAuthAppDO appDO = createAppDO(true, 5);
        appDO.setRenewRefreshTokenEnabled("true");
        appDO.setGracefulRefreshTokenRotationValidityPeriod(30);

        when(mockAccessTokenDAO.getActiveAccessTokensByConsumerUserScopeBinding(
                anyString(), any(), anyString(), anyString(), anyString()))
                .thenReturn(Collections.emptyList());

        OAuthTokenReqMessageContext ctx = createTokenReqCtx(TEST_TENANT_DOMAIN);
        ctx.addProperty(DefaultRefreshTokenGrantProcessor.PREV_ACCESS_TOKEN, oldToken);
        ctx.addProperty(AccessTokenIssuer.OAUTH_APP_DO, appDO);

        AccessTokenDO newToken = new AccessTokenDO();
        newToken.setAccessToken("new_access_token");

        processor.persistNewToken(ctx, newToken, TEST_USER_STORE_DOMAIN, TEST_CONSUMER_KEY);

        ArgumentCaptor<Map> mapCaptor = ArgumentCaptor.forClass(Map.class);
        verify(mockAccessTokenDAO).gracefullyRotateAndCreateNewAccessToken(
                eq(TEST_TOKEN_ID), any(Timestamp.class), anyLong(), anyString(), anyString(),
                eq(TEST_CONSUMER_KEY), eq(newToken), eq(TEST_USER_STORE_DOMAIN),
                eq(TEST_GRANT_TYPE), mapCaptor.capture());
        Map<String, String> capturedUpdates = mapCaptor.getValue();
        assertFalse(capturedUpdates.containsKey(REUSE_COUNT_KEY),
                "No reuse → reuse count must not be stamped on first rotation");
        assertEquals(capturedUpdates.get(
                OAuthConstants.GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_ORIGINAL_VALIDITY_IN_MILLIS),
                Long.toString(oldToken.getValidityPeriodInMillis()),
                "First rotation must anchor the original refresh-token validity on the old row");
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testPersistNewToken_GracefulRotation_WithNewerSibling_CountIncrement() throws Exception {

        Timestamp oldIssuedTime = new Timestamp(System.currentTimeMillis() - 120_000);
        RefreshTokenValidationDataDO oldToken = createValidationBean();
        oldToken.setIssuedTime(oldIssuedTime);
        oldToken.setAccessTokenExtendedAttributes(null);

        OAuthAppDO appDO = createAppDO(true, 5);
        appDO.setRenewRefreshTokenEnabled("true");
        appDO.setGracefulRefreshTokenRotationValidityPeriod(30);

        // sibling was issued AFTER the old token → hasNewerSibling = true
        AccessTokenDO sibling = new AccessTokenDO();
        sibling.setTokenId("sibling_token_id");
        sibling.setAccessToken("sibling_access_token");
        sibling.setRefreshTokenIssuedTime(new Timestamp(System.currentTimeMillis() - 60_000));

        when(mockAccessTokenDAO.getActiveAccessTokensByConsumerUserScopeBinding(
                anyString(), any(), anyString(), anyString(), anyString()))
                .thenReturn(Collections.singletonList(sibling));

        OAuthTokenReqMessageContext ctx = createTokenReqCtx(TEST_TENANT_DOMAIN);
        ctx.addProperty(DefaultRefreshTokenGrantProcessor.PREV_ACCESS_TOKEN, oldToken);
        ctx.addProperty(AccessTokenIssuer.OAUTH_APP_DO, appDO);

        AccessTokenDO newToken = new AccessTokenDO();
        newToken.setAccessToken("new_access_token");

        processor.persistNewToken(ctx, newToken, TEST_USER_STORE_DOMAIN, TEST_CONSUMER_KEY);

        ArgumentCaptor<Map> mapCaptor = ArgumentCaptor.forClass(Map.class);
        verify(mockAccessTokenDAO).gracefullyRotateAndCreateNewAccessToken(
                eq(TEST_TOKEN_ID), any(Timestamp.class), anyLong(), isNull(), isNull(),
                eq(TEST_CONSUMER_KEY), eq(newToken), eq(TEST_USER_STORE_DOMAIN),
                eq(TEST_GRANT_TYPE), mapCaptor.capture());

        Map<String, String> updates = (Map<String, String>) mapCaptor.getValue();
        assertEquals(updates.get(REUSE_COUNT_KEY), "1",
                "First reuse of old token should stamp count=1");
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testPersistNewToken_GracefulRotation_ExistingCount2_Reuse_CountBecomes3() throws Exception {

        Timestamp oldIssuedTime = new Timestamp(System.currentTimeMillis() - 180_000);
        RefreshTokenValidationDataDO oldToken = createValidationBean();
        oldToken.setIssuedTime(oldIssuedTime);
        Map<String, String> existingAttrs = new HashMap<>();
        existingAttrs.put(REUSE_COUNT_KEY, "2");
        oldToken.setAccessTokenExtendedAttributes(new AccessTokenExtendedAttributes(existingAttrs));

        OAuthAppDO appDO = createAppDO(true, 5);
        appDO.setRenewRefreshTokenEnabled("true");
        appDO.setGracefulRefreshTokenRotationValidityPeriod(30);

        AccessTokenDO sibling = new AccessTokenDO();
        sibling.setTokenId("sibling_id");
        sibling.setAccessToken("sibling_at");
        sibling.setRefreshTokenIssuedTime(new Timestamp(System.currentTimeMillis() - 60_000));

        when(mockAccessTokenDAO.getActiveAccessTokensByConsumerUserScopeBinding(
                anyString(), any(), anyString(), anyString(), anyString()))
                .thenReturn(Collections.singletonList(sibling));
        when(mockAccessTokenDAO.getAccessTokenExtendedAttributeValue(anyString(), anyString()))
                .thenReturn("2");

        OAuthTokenReqMessageContext ctx = createTokenReqCtx(TEST_TENANT_DOMAIN);
        ctx.addProperty(DefaultRefreshTokenGrantProcessor.PREV_ACCESS_TOKEN, oldToken);
        ctx.addProperty(AccessTokenIssuer.OAUTH_APP_DO, appDO);

        AccessTokenDO newToken = new AccessTokenDO();
        newToken.setAccessToken("new_access_token");

        processor.persistNewToken(ctx, newToken, TEST_USER_STORE_DOMAIN, TEST_CONSUMER_KEY);

        ArgumentCaptor<Map> mapCaptor = ArgumentCaptor.forClass(Map.class);
        verify(mockAccessTokenDAO).gracefullyRotateAndCreateNewAccessToken(
                any(), any(), anyLong(), isNull(), isNull(), anyString(), any(), anyString(), anyString(),
                mapCaptor.capture());

        assertEquals(((Map<String, String>) mapCaptor.getValue()).get(REUSE_COUNT_KEY), "3");
    }

    @Test
    public void testPersistNewToken_GracefulRotationDisabled_FallsBackToInvalidate() throws Exception {

        RefreshTokenValidationDataDO oldToken = createValidationBean();
        oldToken.setIssuedTime(new Timestamp(System.currentTimeMillis() - 60_000));

        OAuthAppDO appDO = createAppDO(false, 5);
        appDO.setRenewRefreshTokenEnabled("true");

        OAuthTokenReqMessageContext ctx = createTokenReqCtx(TEST_TENANT_DOMAIN);
        ctx.addProperty(DefaultRefreshTokenGrantProcessor.PREV_ACCESS_TOKEN, oldToken);
        ctx.addProperty(AccessTokenIssuer.OAUTH_APP_DO, appDO);

        AccessTokenDO newToken = new AccessTokenDO();
        newToken.setAccessToken("new_access_token");

        processor.persistNewToken(ctx, newToken, TEST_USER_STORE_DOMAIN, TEST_CONSUMER_KEY);

        verify(mockAccessTokenDAO).invalidateAndCreateNewAccessToken(
                eq(TEST_TOKEN_ID), eq(OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE),
                eq(TEST_CONSUMER_KEY), anyString(), eq(newToken), eq(TEST_USER_STORE_DOMAIN),
                eq(TEST_GRANT_TYPE));
        verify(mockAccessTokenDAO, never()).gracefullyRotateAndCreateNewAccessToken(
                anyString(), any(), anyLong(), anyString(), anyString(), anyString(), any(),
                anyString(), anyString(), any());
    }

    // ===================== computeReuseCount (via persistNewToken) =====================

    @Test
    @SuppressWarnings("unchecked")
    public void testComputeReuseCount_NullExtendedAttributes_ReturnsZero_NoStamp() throws Exception {

        RefreshTokenValidationDataDO oldToken = createValidationBean();
        oldToken.setIssuedTime(new Timestamp(System.currentTimeMillis() - 60_000));
        oldToken.setAccessTokenExtendedAttributes(null);

        OAuthAppDO appDO = createAppDO(true, 5);
        appDO.setRenewRefreshTokenEnabled("true");
        appDO.setGracefulRefreshTokenRotationValidityPeriod(30);

        // No siblings → isRefreshTokenReuse = false → count stays 0
        when(mockAccessTokenDAO.getActiveAccessTokensByConsumerUserScopeBinding(
                anyString(), any(), anyString(), anyString(), anyString()))
                .thenReturn(Collections.emptyList());

        OAuthTokenReqMessageContext ctx = createTokenReqCtx(TEST_TENANT_DOMAIN);
        ctx.addProperty(DefaultRefreshTokenGrantProcessor.PREV_ACCESS_TOKEN, oldToken);
        ctx.addProperty(AccessTokenIssuer.OAUTH_APP_DO, appDO);

        processor.persistNewToken(ctx, new AccessTokenDO(), TEST_USER_STORE_DOMAIN, TEST_CONSUMER_KEY);

        // First rotation: reuse count is 0, so oldRowUpdates must not contain REUSE_COUNT and the
        // old row must be transitioned to GRACEFULLY_ROTATED (state-id non-null, validity > 0).
        ArgumentCaptor<Map> mapCaptor = ArgumentCaptor.forClass(Map.class);
        verify(mockAccessTokenDAO).gracefullyRotateAndCreateNewAccessToken(
                any(), any(), longThat(v -> v > 0), anyString(), anyString(),
                anyString(), any(), anyString(), anyString(), mapCaptor.capture());
        assertFalse(((Map<String, String>) mapCaptor.getValue()).containsKey(REUSE_COUNT_KEY),
                "REUSE_COUNT must not be in oldRowUpdates on the first rotation");
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testComputeReuseCount_UnparseableExistingCount_TreatedAsZero() throws Exception {

        RefreshTokenValidationDataDO oldToken = createValidationBean();
        oldToken.setIssuedTime(new Timestamp(System.currentTimeMillis() - 120_000));
        Map<String, String> existingAttrs = new HashMap<>();
        existingAttrs.put(REUSE_COUNT_KEY, "garbage");
        oldToken.setAccessTokenExtendedAttributes(new AccessTokenExtendedAttributes(existingAttrs));

        OAuthAppDO appDO = createAppDO(true, 5);
        appDO.setRenewRefreshTokenEnabled("true");
        appDO.setGracefulRefreshTokenRotationValidityPeriod(30);

        // Sibling with newer issued time → isRefreshTokenReuse = true, oldCount treated as 0, so new count = 1
        AccessTokenDO sibling = new AccessTokenDO();
        sibling.setTokenId("sib");
        sibling.setAccessToken("sib_at");
        sibling.setRefreshTokenIssuedTime(new Timestamp(System.currentTimeMillis() - 60_000));
        when(mockAccessTokenDAO.getActiveAccessTokensByConsumerUserScopeBinding(
                anyString(), any(), anyString(), anyString(), anyString()))
                .thenReturn(Collections.singletonList(sibling));

        OAuthTokenReqMessageContext ctx = createTokenReqCtx(TEST_TENANT_DOMAIN);
        ctx.addProperty(DefaultRefreshTokenGrantProcessor.PREV_ACCESS_TOKEN, oldToken);
        ctx.addProperty(AccessTokenIssuer.OAUTH_APP_DO, appDO);

        processor.persistNewToken(ctx, new AccessTokenDO(), TEST_USER_STORE_DOMAIN, TEST_CONSUMER_KEY);

        ArgumentCaptor<Map> mapCaptor = ArgumentCaptor.forClass(Map.class);
        verify(mockAccessTokenDAO).gracefullyRotateAndCreateNewAccessToken(
                any(), any(), anyLong(), isNull(), isNull(), anyString(), any(), anyString(), anyString(),
                mapCaptor.capture());
        assertEquals(((Map<String, String>) mapCaptor.getValue()).get(REUSE_COUNT_KEY), "1");
    }

    // ===================== revokeStaleSiblings (via persistNewToken) =====================

    @Test
    public void testRevokeStaleSiblings_NoSiblings_ReturnsFalse_NoRevoke() throws Exception {

        RefreshTokenValidationDataDO oldToken = createValidationBean();
        oldToken.setIssuedTime(new Timestamp(System.currentTimeMillis() - 60_000));

        OAuthAppDO appDO = createAppDO(true, 5);
        appDO.setRenewRefreshTokenEnabled("true");
        appDO.setGracefulRefreshTokenRotationValidityPeriod(30);

        when(mockAccessTokenDAO.getActiveAccessTokensByConsumerUserScopeBinding(
                anyString(), any(), anyString(), anyString(), anyString()))
                .thenReturn(Collections.emptyList());

        OAuthTokenReqMessageContext ctx = createTokenReqCtx(TEST_TENANT_DOMAIN);
        ctx.addProperty(DefaultRefreshTokenGrantProcessor.PREV_ACCESS_TOKEN, oldToken);
        ctx.addProperty(AccessTokenIssuer.OAUTH_APP_DO, appDO);

        processor.persistNewToken(ctx, new AccessTokenDO(), TEST_USER_STORE_DOMAIN, TEST_CONSUMER_KEY);

        verify(mockAccessTokenDAO, never()).revokeAccessTokens(any(String[].class));
    }

    @Test
    public void testRevokeStaleSiblings_SiblingWithOlderIssuedTime_ReturnsFalse() throws Exception {

        Timestamp oldIssuedTime = new Timestamp(System.currentTimeMillis() - 60_000);
        RefreshTokenValidationDataDO oldToken = createValidationBean();
        oldToken.setIssuedTime(oldIssuedTime);

        OAuthAppDO appDO = createAppDO(true, 5);
        appDO.setRenewRefreshTokenEnabled("true");
        appDO.setGracefulRefreshTokenRotationValidityPeriod(30);

        // sibling issued BEFORE the old token → hasNewerSibling stays false
        AccessTokenDO sibling = new AccessTokenDO();
        sibling.setTokenId("sibling_id");
        sibling.setAccessToken("sibling_at");
        sibling.setRefreshTokenIssuedTime(new Timestamp(System.currentTimeMillis() - 120_000));

        when(mockAccessTokenDAO.getActiveAccessTokensByConsumerUserScopeBinding(
                anyString(), any(), anyString(), anyString(), anyString()))
                .thenReturn(Collections.singletonList(sibling));

        OAuthTokenReqMessageContext ctx = createTokenReqCtx(TEST_TENANT_DOMAIN);
        ctx.addProperty(DefaultRefreshTokenGrantProcessor.PREV_ACCESS_TOKEN, oldToken);
        ctx.addProperty(AccessTokenIssuer.OAUTH_APP_DO, appDO);

        processor.persistNewToken(ctx, new AccessTokenDO(), TEST_USER_STORE_DOMAIN, TEST_CONSUMER_KEY);

        // sibling should still be revoked (stale cleanup), but isRefreshTokenReuse should be false → count = 0
        verify(mockAccessTokenDAO).revokeAccessTokens(eq(new String[]{"sibling_at"}));

        // Capture the map to verify no reuse stamp
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map> mapCaptor = ArgumentCaptor.forClass(Map.class);
        verify(mockAccessTokenDAO).gracefullyRotateAndCreateNewAccessToken(
                any(), any(), anyLong(), anyString(), anyString(), anyString(), any(), anyString(), anyString(),
                mapCaptor.capture());
        Map<String, String> capturedUpdates = (Map<String, String>) mapCaptor.getValue();
        assertFalse(capturedUpdates.containsKey(REUSE_COUNT_KEY),
                "Older sibling means no reuse → no reuse-count stamp");
        assertEquals(capturedUpdates.get(
                OAuthConstants.GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_ORIGINAL_VALIDITY_IN_MILLIS),
                Long.toString(oldToken.getValidityPeriodInMillis()),
                "First rotation must anchor the original refresh-token validity on the old row");
    }

    @Test
    public void testRevokeStaleSiblings_SiblingWithNewerIssuedTime_ReturnsTrue() throws Exception {

        Timestamp oldIssuedTime = new Timestamp(System.currentTimeMillis() - 120_000);
        RefreshTokenValidationDataDO oldToken = createValidationBean();
        oldToken.setIssuedTime(oldIssuedTime);

        OAuthAppDO appDO = createAppDO(true, 5);
        appDO.setRenewRefreshTokenEnabled("true");
        appDO.setGracefulRefreshTokenRotationValidityPeriod(30);

        AccessTokenDO sibling = new AccessTokenDO();
        sibling.setTokenId("newer_sibling_id");
        sibling.setAccessToken("newer_sibling_at");
        sibling.setRefreshTokenIssuedTime(new Timestamp(System.currentTimeMillis() - 30_000));

        when(mockAccessTokenDAO.getActiveAccessTokensByConsumerUserScopeBinding(
                anyString(), any(), anyString(), anyString(), anyString()))
                .thenReturn(Collections.singletonList(sibling));

        OAuthTokenReqMessageContext ctx = createTokenReqCtx(TEST_TENANT_DOMAIN);
        ctx.addProperty(DefaultRefreshTokenGrantProcessor.PREV_ACCESS_TOKEN, oldToken);
        ctx.addProperty(AccessTokenIssuer.OAUTH_APP_DO, appDO);

        processor.persistNewToken(ctx, new AccessTokenDO(), TEST_USER_STORE_DOMAIN, TEST_CONSUMER_KEY);

        verify(mockAccessTokenDAO).revokeAccessTokens(eq(new String[]{"newer_sibling_at"}));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map> mapCaptor = ArgumentCaptor.forClass(Map.class);
        verify(mockAccessTokenDAO).gracefullyRotateAndCreateNewAccessToken(
                any(), any(), anyLong(), isNull(), isNull(), anyString(), any(), anyString(), anyString(),
                mapCaptor.capture());
        assertFalse(((Map<?, ?>) mapCaptor.getValue()).isEmpty(),
                "Newer sibling means reuse → map should contain the count");
        assertEquals(((Map<String, String>) mapCaptor.getValue()).get(REUSE_COUNT_KEY), "1");
    }

    // ===================== Helper methods =====================

    private OAuthTokenReqMessageContext createTokenReqCtx(String tenantDomain) {

        OAuth2AccessTokenReqDTO dto = new OAuth2AccessTokenReqDTO();
        dto.setClientId(TEST_CONSUMER_KEY);
        dto.setRefreshToken(TEST_REFRESH_TOKEN);
        dto.setTenantDomain(tenantDomain);
        dto.setGrantType(OAuthConstants.GrantTypes.REFRESH_TOKEN);
        return new OAuthTokenReqMessageContext(dto);
    }

    private RefreshTokenValidationDataDO createValidationBean() {

        RefreshTokenValidationDataDO bean = new RefreshTokenValidationDataDO();
        bean.setRefreshToken(TEST_REFRESH_TOKEN);
        bean.setAccessToken(TEST_ACCESS_TOKEN);
        bean.setTokenId(TEST_TOKEN_ID);
        bean.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        bean.setGrantType(TEST_GRANT_TYPE);
        bean.setScope(TEST_SCOPE);
        bean.setAuthorizedUser(createAuthenticatedUser());
        bean.setTokenBindingReference("NONE");
        return bean;
    }

    private OAuthAppDO createAppDO(boolean gracefulRotationEnabled, int reuseLimit) {

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setGracefulRefreshTokenRotationEnabled(gracefulRotationEnabled);
        appDO.setGracefulRefreshTokenReuseLimit(reuseLimit);
        appDO.setGracefulRefreshTokenRotationValidityPeriod(30);
        appDO.setRefreshTokenExpiryTime(3600L);
        appDO.setAppOwner(createAuthenticatedUser());
        return appDO;
    }

    private AuthenticatedUser createAuthenticatedUser() {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName("testuser");
        user.setTenantDomain(TEST_TENANT_DOMAIN);
        user.setUserStoreDomain(TEST_USER_STORE_DOMAIN);
        return user;
    }

    private void closeMockSafely(MockedStatic<?> mock) {

        if (mock != null) {
            try {
                mock.close();
            } catch (Exception e) {
                // Ignore if already closed.
            }
        }
    }
}
