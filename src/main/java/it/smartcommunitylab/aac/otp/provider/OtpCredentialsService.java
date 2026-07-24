package it.smartcommunitylab.aac.otp.provider;

import it.smartcommunitylab.aac.SystemKeys;
import it.smartcommunitylab.aac.common.NoSuchUserException;
import it.smartcommunitylab.aac.common.RegistrationException;
import it.smartcommunitylab.aac.common.SystemException;
import it.smartcommunitylab.aac.core.entrypoint.RealmAwareUriBuilder;
import it.smartcommunitylab.aac.credentials.base.AbstractCredentialsService;
import it.smartcommunitylab.aac.credentials.persistence.UserCredentialsService;
import it.smartcommunitylab.aac.internal.model.InternalUserAccount;
import it.smartcommunitylab.aac.internal.service.InternalJpaUserAccountService;
import it.smartcommunitylab.aac.internal.service.InternalUserConfirmKeyService;
import it.smartcommunitylab.aac.otp.model.InternalEditableUserOtp;
import it.smartcommunitylab.aac.otp.model.InternalUserOtp;
import it.smartcommunitylab.aac.utils.MailService;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import javax.mail.MessagingException;
import org.springframework.util.Assert;

public class OtpCredentialsService
    extends AbstractCredentialsService<
        InternalUserOtp,
        InternalEditableUserOtp,
        OtpIdentityProviderConfigMap,
        OtpCredentialsServiceConfig
    > {

    private final InternalUserConfirmKeyService confirmKeyService;
    private final InternalJpaUserAccountService accountService;
    private final String repositoryId;

    public OtpCredentialsService(
        String providerId,
        UserCredentialsService<InternalUserOtp> credentialsService,
        InternalUserConfirmKeyService confirmKeyService,
        InternalJpaUserAccountService accountService,
        String repositoryId,
        OtpCredentialsServiceConfig providerConfig,
        String realm
    ) {
        super(SystemKeys.AUTHORITY_OTP, providerId, credentialsService, providerConfig, realm);
        Assert.notNull(confirmKeyService, "confirmKeyService is mandatory");
        Assert.notNull(accountService, "accountService is mandatory");
        this.confirmKeyService = confirmKeyService;
        this.accountService = accountService;
        this.repositoryId = repositoryId;
    }

    private MailService mailService;
    private RealmAwareUriBuilder uriBuilder;

    public void setMailService(MailService mailService) {
        this.mailService = mailService;
    }

    public void setUriBuilder(RealmAwareUriBuilder uriBuilder) {
        this.uriBuilder = uriBuilder;
    }

    /**
     * Generates and sends OTP.
     */
    public void generateOtp(String username) throws RegistrationException, NoSuchUserException {
        InternalUserAccount account = accountService.findAccountById(repositoryId, username);
        if (account == null) throw new NoSuchUserException();

        // Rate limiting check: se deadline attiva, blocca.
        if (account.getConfirmationDeadline() != null && account.getConfirmationDeadline().after(new Date())) {
            throw new RegistrationException("rate-limit-exceeded");
        }

        // Imposta deadline (5 min) anche per nuovi tentativi post-blocco
        account.setConfirmationDeadline(new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(5)));

        String code = UUID.randomUUID().toString();
        account.setConfirmationKey(code);
        account.setConfirmationDeadline(new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(5)));
        accountService.updateAccount(repositoryId, account.getUsername(), account);

        try {
            sendOtpMail(account, code, account.getLang());
        } catch (MessagingException e) {
            throw new SystemException(e.getMessage());
        }
    }

    private void sendOtpMail(InternalUserAccount account, String code, String lang) throws MessagingException {
        if (mailService != null) {
            Map<String, Object> vars = new HashMap<>();
            vars.put("code", code);
            vars.put("user", account);

            String link = "";
            if (uriBuilder != null) {
                link = uriBuilder.buildUrl(getRealm(), "/otp/verify/" + code);
            }
            vars.put("link", link);

            Map<String, Object> action = new HashMap<>();
            action.put("url", link);
            action.put("text", "action.login");
            vars.put("action", action);

            mailService.sendEmail(account.getEmail(), "otp", lang, vars);
        }
    }

    public boolean verifyOtp(String username, String token) throws NoSuchUserException {
        InternalUserAccount account = confirmKeyService.findAccountByConfirmationKey(repositoryId, token);
        return account != null && account.getUsername().equals(username);
    }

    @Override
    public String getRegisterUrl() {
        return uriBuilder.buildUrl(getRealm(), "/otp/register");
    }

    @Override
    public String getEditUrl(String credentialsId) {
        return uriBuilder.buildUrl(getRealm(), "/otp/edit/" + credentialsId);
    }
}
