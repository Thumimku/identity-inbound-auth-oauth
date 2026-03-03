/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.impersonation.validators;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannels;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationContext;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationRequestDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.user.api.UserStoreManager;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.NOTIFICATION_CHANNEL;

/**
 * POC impersonation validator that sends an SMS OTP to the subject user
 * before impersonation begins, allowing the subject to consent by sharing
 * the OTP offline with the impersonator.
 *
 * This validator always sets validated = true. The OTP sending is informational
 * for this proof-of-concept; actual OTP verification is out of scope.
 */
public class ImpersonationSmsOtpValidator implements ImpersonationValidator {

    private static final String NAME = "ImpersonationSmsOtpValidator";
    private static final Log LOG = LogFactory.getLog(ImpersonationSmsOtpValidator.class);

    private static final String MOBILE_CLAIM_URI = "http://wso2.org/claims/mobile";
    private static final String TEMPLATE_TYPE = "TEMPLATE_TYPE";
    private static final String SMS_TEMPLATE_NAME = "ImpersonationOTPSMSNotification";
    private static final String SEND_TO = "send-to";
    private static final String OTP_CODE = "otp-code";
    private static final String TRIGGER_SMS_NOTIFICATION = "TRIGGER_SMS_NOTIFICATION_LOCAL";
    private static final int OTP_LENGTH = 6;
    private static final int OTP_BOUND = 1000000;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Override
    public int getPriority() {

        return 150;
    }

    @Override
    public String getImpersonationValidatorName() {

        return NAME;
    }

    @Override
    public ImpersonationContext validateImpersonation(ImpersonationContext impersonationContext) {

        try {
            ImpersonationRequestDTO impersonationRequestDTO = impersonationContext.getImpersonationRequestDTO();
            AuthenticatedUser impersonator = impersonationRequestDTO.getImpersonator();
            AuthenticatedUser subjectUser = impersonator.getImpersonatedUser();

            String subjectUserName = subjectUser.getUserName();
            String subjectTenantDomain = subjectUser.getTenantDomain();
            String subjectUserStoreDomain = subjectUser.getUserStoreDomain();
            String clientId = impersonationRequestDTO.getClientId();

            // Retrieve the subject's mobile number from user claims.
            String mobile = getMobileNumber(subjectUserName, subjectTenantDomain);

            if (StringUtils.isBlank(mobile)) {
                LOG.warn("[POC] ImpersonationSmsOtpValidator: No mobile number found for subject user: "
                        + subjectUserName + ". Skipping SMS OTP.");
            } else {
                // Generate a 6-digit OTP.
                String otp = generateOtp();

                LOG.info("[POC] ImpersonationSmsOtpValidator: Subject=" + subjectUserName
                        + ", Mobile=" + mobile + ", OTP=" + otp
                        + ", Impersonator=" + impersonator.getUserName()
                        + ", ClientId=" + clientId);

                // Send SMS notification.
                sendSmsNotification(subjectUserName, subjectTenantDomain, subjectUserStoreDomain, mobile, otp);

                LOG.info("[POC] ImpersonationSmsOtpValidator: SMS OTP sent successfully to " + mobile);
            }
        } catch (Exception e) {
            String errorMsg = "[POC] ImpersonationSmsOtpValidator: Error occurred while sending SMS OTP, detail: "
                    + e.getMessage();
            /*
             * We are not throwing any exception from here, because this validator should not break the main
             * impersonation flow.
             */
            LOG.warn(errorMsg);
            if (LOG.isDebugEnabled()) {
                LOG.debug(errorMsg, e);
            }
        }

        // Always set validated to true — this is a POC and should not block impersonation.
        impersonationContext.setValidated(true);
        return impersonationContext;
    }

    /**
     * Retrieves the mobile number for the given user from the user store.
     */
    private String getMobileNumber(String username, String tenantDomain) throws Exception {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        UserStoreManager userStoreManager = OAuth2ServiceComponentHolder.getInstance()
                .getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();
        Map<String, String> claimValues = userStoreManager.getUserClaimValues(
                username, new String[]{MOBILE_CLAIM_URI}, null);
        return claimValues.get(MOBILE_CLAIM_URI);
    }

    /**
     * Generates a 6-digit OTP using SecureRandom.
     */
    private String generateOtp() {

        int otp = SECURE_RANDOM.nextInt(OTP_BOUND);
        return String.format("%0" + OTP_LENGTH + "d", otp);
    }

    /**
     * Sends an SMS notification with the OTP to the subject user.
     */
    private void sendSmsNotification(String username, String tenantDomain, String userStoreDomain,
                                     String mobile, String otp) throws Exception {

        Map<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, username);
        properties.put(NOTIFICATION_CHANNEL, NotificationChannels.SMS_CHANNEL.getChannelType());
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, tenantDomain);
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, userStoreDomain);
        properties.put(TEMPLATE_TYPE, SMS_TEMPLATE_NAME);
        properties.put(SEND_TO, mobile);
        properties.put(OTP_CODE, otp);

        Event identityEvent = new Event(TRIGGER_SMS_NOTIFICATION, properties);
        OAuth2ServiceComponentHolder.getIdentityEventService().handleEvent(identityEvent);
    }
}
