package it.smartcommunitylab.aac.spid.provider;

import it.smartcommunitylab.aac.crypto.CertificateParser;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SigningCredentialHelper {

    /*
     * Defines the three distinct lifecycles of SAML credentials in a SPID environment:
     * - AUTH_REQUEST: The active key pair used to sign outbound login requests.
     * - METADATA_SIGNATURE: The active key pair used to cryptographically sign the metadata XML.
     * - METADATA_EXPOSURE: All configured certificates (public parts) exposed for SPID key rotation.
     */
    public enum CredentialPurpose {
        AUTH_REQUEST,
        METADATA_SIGNATURE,
        METADATA_EXPOSURE
    }

    // Resolves validated SPID credentials for the given operation.
    // Ensures compliance with AgID technical regulations for Circle of Trust.
    public static List<SigningCredential> signingCredentialList(SpidIdentityProviderConfigMap configMap, CredentialPurpose purpose) throws IOException, CertificateException {
        List<SigningCredential> signingCredentialList = new ArrayList<>();

        // 1. Safely retrieve the credentials list to avoid NullPointerExceptions
        List<SigningCredential> allCredentials = configMap.getSigningCredentials() != null
            ? configMap.getSigningCredentials()
            : Collections.emptyList();

        // 2. Check if all credentials are inserted correctly
        checkInsertSigningCredentialList(allCredentials);
        checkInsertStandalone(configMap.getSigningKey(), configMap.getSigningCertificate());

        // 3. Determine the population strategy based on the intended purpose
        if (purpose == CredentialPurpose.AUTH_REQUEST || purpose == CredentialPurpose.METADATA_SIGNATURE) {
            SigningCredential credential = populateSpecificSigningCredential(allCredentials, configMap, purpose);
            if (credential != null) {
                signingCredentialList.add(credential);
            }
        } else {
            signingCredentialList.addAll(populateForMetadataExposure(allCredentials, configMap.getSigningKey(), configMap.getSigningCertificate()));
        }

        // 4. Final safety check: if no valid credentials were found/processed,
        if (signingCredentialList.isEmpty()) {
            throw new IllegalArgumentException("CRITICAL: Missing SPID signing credentials. " +
                "The Service Provider cannot establish a Circle of Trust with IdPs " +
                "as required by AgID technical regulations (Binding HTTP-POST/Redirect).");
        }

        return signingCredentialList;
    }

    // Selects signing credentials based on priority: activeId -> standalone -> list fallback.
    // Throws exception if an explicit ID is required but missing or invalid.
    private static SigningCredential populateSpecificSigningCredential(List<SigningCredential> allCredentials, SpidIdentityProviderConfigMap configMap, CredentialPurpose purpose) {
        String activeId = purpose.equals(CredentialPurpose.AUTH_REQUEST)
            ? configMap.getActiveAuthRequestSigningCredentialId()
            : configMap.getActiveMetadataSigningCredentialId();

        // POLICY 1: Select the credential matching the activeId (if an ID is configured)
        if (StringUtils.hasText(activeId)) {
            SigningCredential credential = allCredentials.stream()
                .filter(c -> activeId.equals(c.getCredentialId()))
                .findFirst().orElse(null);

            if (credential == null) {
                throw new IllegalArgumentException("CRITICAL: Not found credential matching active ID '" + activeId + "' for " + getPurposeMsg(purpose) + ".");
            }
            if (!isValidKeyPair(credential.getSigningKey(), credential.getSigningCertificate())) {
                throw new IllegalArgumentException("CRITICAL: Key and Certificate mismatch in ID '" + activeId + "' for " + getPurposeMsg(purpose) + ".");
            }
            return credential;
        }

        // POLICY 2: Fallback to standalone configuration (only if valid)
        if (isValidKeyPair(configMap.getSigningKey(), configMap.getSigningCertificate())) {
            return new SigningCredential(null, configMap.getSigningKey(), configMap.getSigningCertificate());
        }

        // POLICY 3: Absolute fallback to the first credential in the list
        if (!allCredentials.isEmpty()) {
            SigningCredential credential = allCredentials.get(0);
            if (!isValidKeyPair(credential.getSigningKey(), credential.getSigningCertificate())) {
                throw new IllegalArgumentException("CRITICAL: Mismatch the Private Key or Certificate required for " + getPurposeMsg(purpose) + ".");
            }
            return credential;
        }

        return null;
    }

    // Collects all unique public certificates for Metadata exposure.
    // Injects dummy keys where private keys are missing to satisfy framework requirements.
    private static List<SigningCredential> populateForMetadataExposure(List<SigningCredential> allCredentials, String standaloneKey, String standaloneCertificate) {
        List<SigningCredential> metadataSigningCredentialList = new ArrayList<>();

        List<SigningCredential> listToProcess = new ArrayList<>();
        listToProcess.add(new SigningCredential(null, standaloneKey, standaloneCertificate));
        listToProcess.addAll(allCredentials);

        Set<String> uniqueCertificateSet = new HashSet<>();

        listToProcess.stream()
            .filter(c -> c != null && StringUtils.hasText(c.getSigningCertificate()))
            // Normalize the string (strip whitespace) and check for duplicates
            .filter(c -> uniqueCertificateSet.add(c.getSigningCertificate().replaceAll("\\s+", "")))
            .forEach(metadataSigningCredentialList::add);

        return metadataSigningCredentialList;
    }

    // Returns a descriptive string based on the credential's purpose.
    private static String getPurposeMsg(CredentialPurpose purpose) {
        return (purpose == CredentialPurpose.AUTH_REQUEST) ? "signing AuthRequests" : "signing Metadata XML";
    }

    // Ensures both key and certificate are present for every credential in the list
    private static void checkInsertSigningCredentialList(List<SigningCredential> signingCredentialList) {
        if (!signingCredentialList.isEmpty()) {
            for (SigningCredential credential : signingCredentialList) {
                if (!StringUtils.hasText(credential.getSigningKey()) || !StringUtils.hasText(credential.getSigningCertificate())) {
                    throw new IllegalArgumentException("CRITICAL: Key missing in list (ID: " + credential.getCredentialId() + ").");
                }
            }
        }
    }

    // Ensures both key and certificate are present together if standalone credentials are used
    private static void checkInsertStandalone(String signingKey, String signingCertificate) {
        // Logical XOR (^) breakdown: (A || B) && !(A && B)
        if (StringUtils.hasText(signingKey) ^ StringUtils.hasText(signingCertificate)) {
            throw new IllegalArgumentException("CRITICAL: Key missing in standalone credential.");
        }
    }

    // Parses PEM strings into a SAML framework-compatible credential.
    public static Saml2X509Credential createSaml2X509Credential(String privateKeyPem, String certificatePem) throws CertificateException, IOException {
        return CertificateParser.genCredentials(
            privateKeyPem,
            certificatePem,
            Saml2X509Credential.Saml2X509CredentialType.SIGNING,
            Saml2X509Credential.Saml2X509CredentialType.DECRYPTION
        );
    }

    // Verifies that a private key matches the modulus of the public certificate.
    private static boolean isValidKeyPair(String privateKeyPem, String certificatePem) {
        try {
            Saml2X509Credential credential = createSaml2X509Credential(privateKeyPem, certificatePem);
            PrivateKey privateKey = credential.getPrivateKey();
            PublicKey publicKey = credential.getCertificate().getPublicKey();

            if (publicKey instanceof RSAPublicKey && privateKey instanceof RSAPrivateKey) {
                return ((RSAPublicKey) publicKey).getModulus().equals(((RSAPrivateKey) privateKey).getModulus());
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }
}
