/*
 * Copyright (c) 2023-2026, WSO2 LLC. (https://www.wso2.com).
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

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.OAuthConstants.GracefulRefreshTokenRotation;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenExtendedAttributes;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.AccessTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OIDCClaimUtil;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Default implementation of @RefreshTokenProcessor responsible for handling refresh token persistence logic.
 */
public class DefaultRefreshTokenGrantProcessor implements RefreshTokenGrantProcessor {

    private static final Log log = LogFactory.getLog(DefaultRefreshTokenGrantProcessor.class);
    public static final String PREV_ACCESS_TOKEN = "previousAccessToken";
    public static final int LAST_ACCESS_TOKEN_RETRIEVAL_LIMIT = 10;

    @Override
    public RefreshTokenValidationDataDO validateRefreshToken(OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO tokenReq = tokenReqMessageContext.getOauth2AccessTokenReqDTO();
        RefreshTokenValidationDataDO validationBean = OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO()
                .validateRefreshToken(tokenReq.getClientId(), tokenReq.getRefreshToken());
        validatePersistedAccessToken(validationBean, tokenReq.getClientId());
        adjustStateAndValidateReuseLimit(validationBean, tokenReq.getClientId(), tokenReq.getTenantDomain());
        return validationBean;
    }

    /**
     * When graceful refresh token rotation is enabled for the application:
     * <ol>
     *   <li>Flips the in-memory token state from {@code GRACEFULLY_ROTATED} back to {@code ACTIVE} so that
     *       downstream validation (validateRefreshTokenStatus, setRefreshTokenData, etc.) sees {@code ACTIVE}.
     *       The DB value stays {@code GRACEFULLY_ROTATED}.</li>
     *   <li>Rejects the request if the reuse count has already reached the app-configured limit.
     *       Missing or unparseable reuse-count attributes are treated as zero (covers first-time issuance,
     *       legacy rows, and custom persistence implementations).</li>
     * </ol>
     * No-op when graceful rotation is disabled or the application cannot be resolved.
     */
    private void adjustStateAndValidateReuseLimit(RefreshTokenValidationDataDO validationBean, String clientId,
                                                  String tenantDomain) throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = StringUtils.isNotBlank(tenantDomain)
                    ? OAuth2Util.getAppInformationByClientId(clientId, tenantDomain)
                    : OAuth2Util.getAppInformationByClientIdOnly(clientId);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving OAuth application for client id: " + clientId, e);
        }
        if (oAuthAppDO == null || !oAuthAppDO.isGracefulRefreshTokenRotationEnabled()) {
            return;
        }
        // (1) Normalise token state in-memory for downstream validation.
        if (OAuthConstants.TokenStates.TOKEN_STATE_GRACEFULLY_ROTATED.equals(
                validationBean.getRefreshTokenState())) {
            validationBean.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        }
        // (2) Enforce reuse limit.
        AccessTokenExtendedAttributes extendedAttributes = validationBean.getAccessTokenExtendedAttributes();
        if (extendedAttributes == null || extendedAttributes.getParameters() == null) {
            return;
        }
        String rawReuseCount = extendedAttributes.getParameters()
                .get(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT);
        if (StringUtils.isBlank(rawReuseCount)) {
            return;
        }
        int reuseCount;
        try {
            reuseCount = Integer.parseInt(rawReuseCount);
        } catch (NumberFormatException e) {
            if (log.isDebugEnabled()) {
                log.debug("Unparseable graceful refresh token reuse count '" + rawReuseCount
                        + "' for client: " + clientId + ". Treating as zero.");
            }
            return;
        }
        int reuseLimit = oAuthAppDO.getGracefulRefreshTokenReuseLimit();
        if (reuseCount >= reuseLimit) {
            if (log.isDebugEnabled()) {
                log.debug("Refresh token reuse limit (" + reuseLimit + ") reached for client: " + clientId
                        + ". Current reuse count: " + reuseCount + ". Rejecting refresh request.");
            }
            throw new IdentityOAuth2Exception("Refresh token has reached the configured graceful reuse limit.");
        }
    }

    @Override
    public void persistNewToken(OAuthTokenReqMessageContext tokenReqMessageContext, AccessTokenDO accessTokenBean,
                                String userStoreDomain, String clientId) throws IdentityOAuth2Exception {

        RefreshTokenValidationDataDO oldAccessToken =
                (RefreshTokenValidationDataDO) tokenReqMessageContext.getProperty(PREV_ACCESS_TOKEN);
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug(String.format("Previous access token (hashed): %s", DigestUtils.sha256Hex(
                        oldAccessToken.getAccessToken())));
            }
        }

        OAuthAppDO oAuthAppDO = (OAuthAppDO) tokenReqMessageContext.getProperty(AccessTokenIssuer.OAUTH_APP_DO);
        if (oAuthAppDO != null && OAuth2Util.isRenewRefreshToken(oAuthAppDO.getRenewRefreshTokenEnabled())
                && oAuthAppDO.isGracefulRefreshTokenRotationEnabled()) {
            // Read the reuse count fresh from DB inside the sync block so a stale pre-lock snapshot
            // cannot bypass the limit or re-anchor the grace window after a sibling thread has rotated.
            String freshRawCount = OAuthTokenPersistenceFactory.getInstance()
                    .getAccessTokenDAOImpl(clientId)
                    .getAccessTokenExtendedAttributeValue(
                            oldAccessToken.getTokenId(),
                            GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT);
            int freshCount = parseReuseCount(freshRawCount);
            if (freshCount >= oAuthAppDO.getGracefulRefreshTokenReuseLimit()) {
                throw new IdentityOAuth2Exception(
                        "Refresh token has reached the configured graceful reuse limit.");
            }
            overlayReuseCountOnAccessToken(oldAccessToken, freshCount);

            boolean isRefreshTokenReuse = revokeStaleSiblings(oldAccessToken, userStoreDomain, clientId);
            int newReuseCount = computeReuseCount(oldAccessToken, isRefreshTokenReuse);
            stampReuseCountOnOldAccessToken(oldAccessToken, newReuseCount);
            Map<String, String> oldRowUpdates = new HashMap<>();
            if (newReuseCount > 0) {
                oldRowUpdates.put(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT,
                        Integer.toString(newReuseCount));
            }

            // Only shorten the old row's refresh validity on the first rotation. On subsequent reuses the deadline
            // is already anchored; recomputing it against the current wall clock would extend the grace window.
            long shortenedRefreshValidity = 0L;
            String oldTokenNewStateId = null;
            String oldTokenNewState = null;
            if (newReuseCount == 0) {
                long elapsedSinceRefreshIssuedMillis =
                        System.currentTimeMillis() - oldAccessToken.getIssuedTime().getTime();
                long graceMillis =
                        TimeUnit.SECONDS.toMillis(oAuthAppDO.getGracefulRefreshTokenRotationValidityPeriod());
                shortenedRefreshValidity = elapsedSinceRefreshIssuedMillis + graceMillis;
                oldTokenNewStateId = UUID.randomUUID().toString();
                oldTokenNewState = OAuthConstants.TokenStates.TOKEN_STATE_GRACEFULLY_ROTATED;
                oldRowUpdates.put(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_ORIGINAL_VALIDITY_IN_MILLIS,
                        Long.toString(oldAccessToken.getValidityPeriodInMillis()));
            }

            OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAOImpl(clientId)
                    .gracefullyRotateAndCreateNewAccessToken(oldAccessToken.getTokenId(),
                            oldAccessToken.getIssuedTime(), shortenedRefreshValidity,
                            oldTokenNewStateId, oldTokenNewState, clientId, accessTokenBean, userStoreDomain,
                            oldAccessToken.getGrantType(), oldRowUpdates);
            return;
        }

        // set the previous access token state to "INACTIVE" and store new access token in single db connection
        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAOImpl(clientId)
                .invalidateAndCreateNewAccessToken(oldAccessToken.getTokenId(),
                        OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE, clientId,
                        UUID.randomUUID().toString(), accessTokenBean, userStoreDomain, oldAccessToken.getGrantType());
    }

    @Override
    public AccessTokenDO createAccessTokenBean(OAuthTokenReqMessageContext tokReqMsgCtx,
                                               OAuth2AccessTokenReqDTO tokenReq,
                                               RefreshTokenValidationDataDO validationBean, String tokenType)
            throws IdentityOAuth2Exception {

        Timestamp timestamp = new Timestamp(new Date().getTime());
        String tokenId = UUID.randomUUID().toString();

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setConsumerKey(tokenReq.getClientId());
        accessTokenDO.setAuthzUser(tokReqMsgCtx.getAuthorizedUser());
        accessTokenDO.setScope(tokReqMsgCtx.getScope());
        accessTokenDO.setTokenType(tokenType);
        accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        accessTokenDO.setTokenId(tokenId);
        accessTokenDO.setGrantType(tokenReq.getGrantType());
        accessTokenDO.setIssuedTime(timestamp);
        String appResidentTenantDomain = OAuth2Util.getAppResidentTenantDomain();
        accessTokenDO.setAppResidentTenantId(StringUtils.isNotBlank(appResidentTenantDomain)
                ? IdentityTenantUtil.getTenantId(appResidentTenantDomain)
                : IdentityTenantUtil.getLoginTenantId());
        accessTokenDO.setTokenBinding(tokReqMsgCtx.getTokenBinding());

        if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
            String previousGrantType = validationBean.getGrantType();
            // Check if the previous grant type is consent refresh token type or not.
            if (!OAuthConstants.GrantTypes.REFRESH_TOKEN.equals(previousGrantType)) {
                // If the previous grant type is not a refresh token, then check if it's a consent token or not.
                if (OIDCClaimUtil.isConsentBasedClaimFilteringApplicable(previousGrantType)) {
                    accessTokenDO.setIsConsentedToken(true);
                }
            } else {
                /* When previousGrantType == refresh_token, we need to check whether the original grant type
                 is consented or not. */
                accessTokenDO.setIsConsentedToken(validationBean.isConsented());
            }

            if (accessTokenDO.isConsentedToken()) {
                tokReqMsgCtx.setConsentedToken(true);
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Setting access token extended attributes for token request in refresh token flow for client: "
                    + tokenReq.getClientId() + " with token id: " + tokenId);
        }
        if (tokenReq.getAccessTokenExtendedAttributes() != null &&
                tokenReq.getAccessTokenExtendedAttributes().getParameters() != null) {
            HashMap<String, String> parameters =
                    new HashMap<>(tokenReq.getAccessTokenExtendedAttributes().getParameters());
            parameters.remove(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT);
            parameters.remove(
                    GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_ORIGINAL_VALIDITY_IN_MILLIS);
            if (!parameters.isEmpty()) {
                accessTokenDO.setAccessTokenExtendedAttributes(new AccessTokenExtendedAttributes(parameters));
            }
        }
        return accessTokenDO;
    }

    private boolean validatePersistedAccessToken(RefreshTokenValidationDataDO validationBean, String clientId)
            throws IdentityOAuth2Exception {

        if (validationBean.getAccessToken() == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Invalid Refresh Token provided for Client with Client Id : %s", clientId));
            }
            throw new IdentityOAuth2Exception("Persisted access token data not found");
        }
        return true;
    }

    @Override
    public boolean isLatestRefreshToken(OAuth2AccessTokenReqDTO tokenReq, RefreshTokenValidationDataDO validationBean,
                                        String userStoreDomain) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.REFRESH_TOKEN)) {
                log.debug(String.format("Evaluating refresh token. Token value(hashed): %s, Token state: %s",
                        DigestUtils.sha256Hex(tokenReq.getRefreshToken()), validationBean.getRefreshTokenState()));
            } else {
                log.debug(String.format("Evaluating refresh token. Token state: %s",
                        validationBean.getRefreshTokenState()));
            }
        }
        if (!OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(validationBean.getRefreshTokenState())) {
            /* if refresh token is not in active state, check whether there is an access token issued with the same
             * refresh token.
             */
            List<AccessTokenDO> accessTokenBeans = getAccessTokenBeans(tokenReq, validationBean, userStoreDomain);
            for (AccessTokenDO token : accessTokenBeans) {
                if (tokenReq.getRefreshToken() != null && tokenReq.getRefreshToken().equals(token.getRefreshToken())
                        && (OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(token.getTokenState())
                        || OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED.equals(token.getTokenState()))) {
                    return true;
                }
            }
            if (log.isDebugEnabled()) {
                log.debug(String.format("Refresh token: %s is not the latest", tokenReq.getRefreshToken()));
            }
            return false;
        }
        return true;
    }

    /**
     * Revoke every ACTIVE sibling token in the same (client, user, scope, binding) chain whose tokenId
     * differs from the one being rotated. Returns true when at least one sibling has an issuedTime
     * later than {@code oldAccessToken} — that means {@code oldAccessToken} is an already-rotated row
     * being re-used (the caller treats this as a "reuse" for counter increment).
     */
    private boolean revokeStaleSiblings(RefreshTokenValidationDataDO oldAccessToken, String userStoreDomain,
                                        String clientId) throws IdentityOAuth2Exception {

        List<AccessTokenDO> siblings = OAuthTokenPersistenceFactory.getInstance()
                .getAccessTokenDAOImpl(clientId)
                .getActiveAccessTokensByConsumerUserScopeBinding(
                        clientId, oldAccessToken.getAuthorizedUser(), userStoreDomain,
                        OAuth2Util.buildScopeString(oldAccessToken.getScope()),
                        oldAccessToken.getTokenBindingReference());
        List<String> siblingTokens = new ArrayList<>();
        List<AccessTokenDO> siblingsToRevoke = new ArrayList<>();
        // If any sibling has a later issuedTime than the old token, that means the old token is an already-rotated
        // row being re-used. In that case we should increment the reuse count;
        // otherwise, this is the first rotation and the old token row is still fresh, so the reuse count stays at zero.
        // Refresh token issued time is not considered here since the siblings may have been issued same issued time
        // if isExtendRenewedRefreshTokenExpiryTime is set to false in the app.
        boolean hasNewerSibling = false;
        Timestamp oldIssuedTime = oldAccessToken.getIssuedTime();
        for (AccessTokenDO sibling : siblings) {
            if (!oldAccessToken.getTokenId().equals(sibling.getTokenId())) {
                siblingTokens.add(sibling.getAccessToken());
                siblingsToRevoke.add(sibling);
                if (oldIssuedTime != null && sibling.getIssuedTime() != null
                        && sibling.getIssuedTime().after(oldIssuedTime)) {
                    hasNewerSibling = true;
                }
            }
        }
        if (siblingTokens.isEmpty()) {
            return hasNewerSibling;
        }
        if (log.isDebugEnabled()) {
            for (AccessTokenDO sibling : siblingsToRevoke) {
                log.debug("Revoking stale sibling access token (hashed): "
                        + DigestUtils.sha256Hex(sibling.getAccessToken())
                        + " for client: " + clientId + " during graceful refresh token rotation.");
            }
        }
        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAOImpl(clientId)
                .revokeAccessTokens(siblingTokens.toArray(new String[0]));
        for (AccessTokenDO sibling : siblingsToRevoke) {
            AuthorizationGrantCacheKey siblingCacheKey =
                    new AuthorizationGrantCacheKey(sibling.getAccessToken());
            AuthorizationGrantCache.getInstance()
                    .clearCacheEntryByTokenId(siblingCacheKey, sibling.getTokenId());
        }
        return hasNewerSibling;
    }

    /**
     * Compute the reuse count to persist on the new token row. Reads the existing count from
     * {@code oldAccessToken}'s extended attributes (defaulting to 0 when absent or unparseable)
     * and increments by one only when this rotation is a reuse of an already-rotated row.
     */
    private int computeReuseCount(RefreshTokenValidationDataDO oldAccessToken, boolean isRefreshTokenReuse) {

        int oldCount = readPersistedReuseCount(oldAccessToken);
        return isRefreshTokenReuse ? oldCount + 1 : oldCount;
    }

    /**
     * Read the graceful reuse count stored in {@code tokenData}'s extended attributes.
     * Returns 0 when absent, blank, or unparseable.
     */
    private int readPersistedReuseCount(RefreshTokenValidationDataDO tokenData) {

        AccessTokenExtendedAttributes attributes = tokenData.getAccessTokenExtendedAttributes();
        if (attributes == null || attributes.getParameters() == null) {
            return 0;
        }
        String rawCount = attributes.getParameters()
                .get(GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT);
        return parseReuseCount(rawCount);
    }

    private int parseReuseCount(String raw) {

        if (StringUtils.isBlank(raw)) {
            return 0;
        }
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /**
     * Update the in-memory extended attributes of the OLD token row with the new reuse count. When
     * {@code newReuseCount} is zero and no attributes exist yet, this is a no-op (avoids creating
     * empty attribute containers for the first-rotation case).
     */
    private void stampReuseCountOnOldAccessToken(RefreshTokenValidationDataDO oldAccessToken,
                                                  int newReuseCount) {

        if (newReuseCount == 0 && oldAccessToken.getAccessTokenExtendedAttributes() == null) {
            return;
        }
        AccessTokenExtendedAttributes attributes = oldAccessToken.getAccessTokenExtendedAttributes();
        if (attributes == null) {
            attributes = new AccessTokenExtendedAttributes(new HashMap<>());
            oldAccessToken.setAccessTokenExtendedAttributes(attributes);
        } else if (attributes.getParameters() == null) {
            attributes.setParameters(new HashMap<>());
        }
        attributes.getParameters().put(
                GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT,
                Integer.toString(newReuseCount));
    }

    private void overlayReuseCountOnAccessToken(RefreshTokenValidationDataDO oldAccessToken, int reuseCount) {

        AccessTokenExtendedAttributes attributes = oldAccessToken.getAccessTokenExtendedAttributes();
        if (attributes == null) {
            attributes = new AccessTokenExtendedAttributes(new HashMap<>());
            oldAccessToken.setAccessTokenExtendedAttributes(attributes);
        } else if (attributes.getParameters() == null) {
            attributes.setParameters(new HashMap<>());
        }
        attributes.getParameters().put(
                GracefulRefreshTokenRotation.GRACEFUL_REFRESH_TOKEN_REUSE_COUNT,
                Integer.toString(reuseCount));
    }

    private List<AccessTokenDO> getAccessTokenBeans(OAuth2AccessTokenReqDTO tokenReq,
                                                    RefreshTokenValidationDataDO validationBean, String userStoreDomain)
            throws IdentityOAuth2Exception {

        List<AccessTokenDO> accessTokenBeans = OAuthTokenPersistenceFactory.getInstance()
                .getAccessTokenDAOImpl(tokenReq.getClientId())
                .getLatestAccessTokens(tokenReq.getClientId(), validationBean.getAuthorizedUser(), userStoreDomain,
                        OAuth2Util.buildScopeString(validationBean.getScope()),
                        validationBean.getTokenBindingReference(), true, LAST_ACCESS_TOKEN_RETRIEVAL_LIMIT);
        if (accessTokenBeans == null || accessTokenBeans.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No previous access tokens found. User: %s, client: %s, scope: %s",
                        validationBean.getAuthorizedUser(), tokenReq.getClientId(),
                        OAuth2Util.buildScopeString(validationBean.getScope())));
            }
            throw new IdentityOAuth2Exception("No previous access tokens found");
        }
        return accessTokenBeans;
    }

    /**
     * Add user attributes to cache against the new access token.
     * @param accessTokenBean Access token data object.
     * @param msgCtx Token request message context.
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void addUserAttributesToCache(AccessTokenDO accessTokenBean, OAuthTokenReqMessageContext msgCtx)
            throws IdentityOAuth2Exception {

        RefreshTokenValidationDataDO oldAccessToken =
                (RefreshTokenValidationDataDO) msgCtx.getProperty(PREV_ACCESS_TOKEN);
        if (oldAccessToken == null || StringUtils.isBlank(oldAccessToken.getAccessToken())) {
            return;
        }
        AuthorizationGrantCacheKey oldAuthorizationGrantCacheKey = new AuthorizationGrantCacheKey(oldAccessToken
                .getAccessToken());
        if (log.isDebugEnabled()) {
            log.debug("Getting AuthorizationGrantCacheEntry using access token id: " + accessTokenBean.getTokenId());
        }
        AuthorizationGrantCacheEntry grantCacheEntry =
                AuthorizationGrantCache.getInstance().getValueFromCacheByTokenId(oldAuthorizationGrantCacheKey,
                        oldAccessToken.getTokenId());

        /*
         * When multiple concurrent refresh token requests occur using the same refresh token,
         * other nodes in the cluster may revoke the cache entries associated with the previous token.
         * However, since the current node is unaware of these deletions, it may fail to retrieve the
         * cache entry for the token. This block ensures that the cache is fetched using the given token ID,
         * even if the cache entry related to the token is marked as deleted.
         * This is done for JWT tokens and federated users only.
         */
        if (grantCacheEntry == null) {
            if (msgCtx.getAuthorizedUser() != null && msgCtx.getAuthorizedUser().isFederatedUser()) {
                OAuthAppDO oAuthAppDO = (OAuthAppDO) msgCtx.getProperty(AccessTokenIssuer.OAUTH_APP_DO);
                if (oAuthAppDO != null && OAuth2Util.JWT.equals(oAuthAppDO.getTokenType())) {
                    grantCacheEntry = AuthorizationGrantCache.getInstance()
                            .getValueFromCacheByTokenId(oldAuthorizationGrantCacheKey, oldAccessToken.getTokenId(),
                                    OAuth2Constants.STORE_OPERATION);
                }
            }
        }

        if (grantCacheEntry != null) {
            if (log.isDebugEnabled()) {
                log.debug("Getting user attributes cached against the previous access token with access token id: " +
                        oldAccessToken.getTokenId());
            }
            AuthorizationGrantCacheKey authorizationGrantCacheKey = new AuthorizationGrantCacheKey(accessTokenBean
                    .getAccessToken());

            // Pre-compute graceful rotation validity before mutating the entry.
            OAuthAppDO oAuthAppDO = (OAuthAppDO) msgCtx.getProperty(AccessTokenIssuer.OAUTH_APP_DO);
            // Only restore the old cache entry with a grace TTL on the first rotation. On reuses the entry
            // already carries the original deadline; recomputing elapsed would push it forward.
            boolean isGracefulRotation = oAuthAppDO != null
                    && OAuth2Util.isRenewRefreshToken(oAuthAppDO.getRenewRefreshTokenEnabled())
                    && oAuthAppDO.isGracefulRefreshTokenRotationEnabled()
                    && readPersistedReuseCount(oldAccessToken) == 0;
            long gracefulValidityNanos = 0;
            if (isGracefulRotation) {
                long elapsedSinceRefreshIssuedMillis =
                        System.currentTimeMillis() - oldAccessToken.getIssuedTime().getTime();
                long graceMillis =
                        TimeUnit.SECONDS.toMillis(oAuthAppDO.getGracefulRefreshTokenRotationValidityPeriod());
                gracefulValidityNanos = TimeUnit.MILLISECONDS.toNanos(elapsedSinceRefreshIssuedMillis + graceMillis);
            }

            if (StringUtils.isNotBlank(accessTokenBean.getTokenId())) {
                grantCacheEntry.setTokenId(accessTokenBean.getTokenId());
            } else {
                grantCacheEntry.setTokenId(null);
            }

            // Setting the validity period of the cache entry to be same as the validity period of the refresh token.
            grantCacheEntry.setValidityPeriod(
                    TimeUnit.MILLISECONDS.toNanos(accessTokenBean.getRefreshTokenValidityPeriodInMillis()));

            // This new method has introduced in order to resolve a regression occurred : wso2/product-is#4366.
            AuthorizationGrantCache.getInstance().clearCacheEntryByTokenId(oldAuthorizationGrantCacheKey,
                    oldAccessToken.getTokenId());
            // If refresh token persistence is disabled and the user is not federated, do not store user attributes.
            // When a user's profile is updated after the token is issued, the cache cannot be cleared because
            // the Identity Server will not persist either the refresh token or the access token. As a result,
            // outdated user attribute data would be returned on the next refresh grant.
            // To mitigate this, user attributes are set to null.
            if (!OAuth2Util.isRefreshTokenPersistenceEnabled() && !accessTokenBean.getAuthzUser().isFederatedUser()) {
                grantCacheEntry.setUserAttributes(null);
            }
            AuthorizationGrantCache.getInstance().addToCacheByToken(authorizationGrantCacheKey, grantCacheEntry);

            // When graceful refresh token rotation is enabled, re-add the old cache entry under the old access
            // token key with the graceful validity period so that the old refresh token remains usable within
            // the grace window.
            if (isGracefulRotation) {
                grantCacheEntry.setTokenId(oldAccessToken.getTokenId());
                grantCacheEntry.setValidityPeriod(gracefulValidityNanos);
                AuthorizationGrantCache.getInstance().addToCacheByToken(oldAuthorizationGrantCacheKey,
                        grantCacheEntry);
            }
        }
    }
}
