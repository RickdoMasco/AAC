# Flussi Operativi dell'Identity Provider Email OTP

Questo documento dettaglia i processi logici e le interazioni tra i componenti per la gestione del ciclo di vita di un One-Time Password (OTP), delegando la gestione delle chiavi all'infrastruttura dell'Internal IDP.

## 1. Flusso di Richiesta OTP

Il flusso di richiesta è progettato per prevenire l'enumerazione degli utenti e proteggere il server SMTP da abusi, riutilizzando il meccanismo di "confirmation key" dell'Internal IDP.

```mermaid
flowchart TD
    A[Inizio: Utente inserisce email] --> B{Account Esistente e Attivo?}
    B -- Sì --> C{Cooldown Scaduto?}
    B -- No --> L[Risposta: 'Se l'account esiste, riceverai un codice']
    C -- Sì --> D[Generazione OTP via InternalUserConfirmKeyService]
    C -- No --> M[Risposta: 'Richiesta troppo frequente']
    D --> E[Persistenza chiave in Internal DB <br/> via ConfirmKeyService]
    E --> F[Invio OTP tramite MailService]
    F --> G[Risposta: 'Codice inviato all'indirizzo email']
    G --> H[Fine]
    L --> H
    M --> H
```

## 2. Flusso di Validazione OTP

La validazione delega l'intera logica di verifica, scadenza e consumo al `InternalUserConfirmKeyService`, garantendo coerenza con le policy di sicurezza globali di AAC.

```mermaid
flowchart TD
    A[Inizio: Utente inserisce email e codice OTP] --> B[Richiesta validazione a InternalUserConfirmKeyService]
    B --> C{Codice Valido?}
    C -- No --> D{Motivo Errore?}
    D -- Scaduto --> E[Errore: 'Codice scaduto']
    D -- Errato --> F[Errore: 'Codice errato']
    D -- Altro --> G[Errore: 'Validazione fallita']
    C -- Sì --> H[Consumo immediato della chiave <br/> via ConfirmKeyService]
    H --> I[Richiesta creazione sessione ad AAC]
    I --> J[Successo: Accesso Garantito]
    J --> K[Fine]
    E --> K
    F --> K
    G --> K
```

## 3. Tabella di Mappatura Responsabilità

| Fase | Componente Responsabile | Azione |
| :--- | :--- | :--- |
| **Identificazione** | `EmailOtpIdentityProvider` | Verifica esistenza account |
| **Generazione** | `InternalUserConfirmKeyService` | Crea chiave sicura e definisce TTL |
| **Notifica** | `MailService` | Invia l'OTP all'utente |
| **Verifica** | `InternalUserConfirmKeyService` | Confronta hash, verifica TTL e tentativi |
| **Sessione** | `AAC Core` | Genera token di autenticazione |
