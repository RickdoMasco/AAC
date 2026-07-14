# Guida all'Implementazione Tecnica - Email OTP

Questo documento fornisce le specifiche tecniche operative per lo sviluppo dell'Identity Provider Email OTP all'interno del framework AAC, integrando nativamente le funzionalità dell'Internal IDP per eliminare ridondanze di codice e database.

## 1. Mappatura delle Componenti Java

L'implementazione segue un approccio di "Zero-Redundancy", delegando la gestione delle chiavi e della persistenza ai servizi core di AAC.

| Classe | Tipo | Estende/Implementa | Responsabilità |
| :--- | :--- | :--- | :--- |
| `EmailOtpIdentityProvider` | Provider | `AbstractIdentityProvider` | Orchestrazione del flusso di login, gestione delle richieste OTP e validazione delegata. |
| `InternalUserConfirmKeyService` | Service | `@Service` (Core) | **Delegato**: Gestione ciclo di vita OTP (generazione, hashing, persistenza, validazione, consumo). |
| `MailService` | Service | `@Service` (Core) | **Delegato**: Invio fisico del codice OTP tramite template email. |
| `EmailOtpIdentityProviderConfig` | Config | `@ConfigurationProperties` | Gestione parametri specifici del provider (es. template email, cooldown). |

## 2. Design della Persistenza (Data Schema)

L'Email OTP non utilizza tabelle dedicate. Sfrutta l'infrastruttura esistente dell'Internal IDP, garantendo che ogni codice sia legato univocamente a un account interno.

**Tabella utilizzata**: `aac_internal_user_confirm_key` (gestita da `InternalUserConfirmKeyService`).

### Vantaggi dell'approccio delegato

- **Consistenza**: Stessa logica di hashing e TTL utilizzata per la conferma account.
- **Sicurezza**: Nessuna duplicazione di logica di sicurezza sensibile (SecureRandom, salt).
- **Manutenibilità**: Modifiche alla policy di sicurezza delle chiavi si riflettono automaticamente sull'OTP senza modifiche al codice del provider.

## 3. Security Implementation Checklist

La sicurezza è garantita per delega al core di AAC. Il provider ha la responsabilità di invocare correttamente i servizi e gestire i limiti di frequenza.

### Generazione e Invio

- [x] **Secure Randomness**: Garantito da `InternalUserConfirmKeyService`.
- [ ] **Rate Limiting**: Implementato controllo cooldown nel provider prima di invocare il servizio di generazione.
- [ ] **Email Privacy**: Template email configurato per mostrare solo l'OTP e nessuna informazione sensibile.

### Validazione e Consumo

- [x] **Atomicità**: Garantita dal servizio di persistenza core (Transazionale).
- [x] **Constant-Time Comparison**: Gestito internamente dalla logica di validazione core.
- [x] **TTL Verification**: Gestito automaticamente tramite campo `expiry_date` del core.
- [x] **Brute Force Protection**: Gestito tramite contatore tentativi implementato nel core.

### Manutenzione

- [x] **Auto-Cleanup**: Gestito dai job di sistema dell'Internal IDP per la pulizia delle chiavi scadute.
- [ ] **Audit Logging**: Il provider deve loggare gli eventi di login OTP (Successo/Fallimento).

## 4. Esempio di Configurazione (YAML)

L'IdP è configurabile tramite il sistema di configurazione centralizzato di AAC:

```yaml
idp:
  email-otp:
    enabled: true
    email-template: "otp-login-template.html"
    cooldown-seconds: 60
```
