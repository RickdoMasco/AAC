# MFA Proof of Concept (PoC) - Implementation Design

Questo documento definisce il design per il Proof of Concept (PoC) della Multi-Factor Authentication (MFA) in AAC. L'obiettivo è validare l'idea di un'autenticazione a più fattori che risulti in un token finale contenente molteplici token di autenticazione interni.

## 1. Concetto Chiave: Multi-Token Authentication
L'attuale implementazione di AAC utilizza `DefaultUserAuthenticationToken`, che è già progettato per supportare più identità e token. Come visto nel codice, la classe possiede un `Set<ExtendedAuthenticationToken> tokens`, permettendo a un singolo utente autenticato di avere più prove di autenticazione associate.

Il PoC mira a implementare un flusso in cui l'utente deve superare due processi di autenticazione distinti per ottenere l'accesso finale.

---

## 2. Logica del Filtro di Sicurezza (MfaPoCFilter)

Il cuore del PoC è un nuovo filtro HTTP inserito nella `SecurityFilterChain`. Il filtro opera secondo la seguente macchina a stati:

### Step-by-Step Flow

1. **Verifica Configurazione Realm**: 
   Il filtro interroga la configurazione del Realm corrente. Se il flag `MFA_REQUIRED` è `false`, il filtro lascia passare la richiesta normalmente. Se è `true`, procede al controllo MFA.

2. **Controllo Token in Sessione**:
   Il filtro controlla l' `HttpSession` alla ricerca di un token precedentemente salvato (es. sotto la chiave `MFA_FIRST_TOKEN`).

3. **Primo Fattore (Intercettazione)**:
   - **Se il token NON è presente**: 
     - L'utente ha appena superato il primo login.
     - Il filtro estrae il token di autenticazione corrente dal `SecurityContext`.
     - Salva questo token nella sessione (`MFA_FIRST_TOKEN`).
     - **Azione**: Esegue un redirect forzato per riavviare il processo di login (indirizzando l'utente verso la pagina di inserimento delle credenziali per il secondo fattore).

4. **Secondo Fattore (Validazione)**:
   - **Se il token È presente**:
     - L'utente è tornato al filtro dopo aver tentato un secondo login.
     - Il filtro recupera il token appena ricevuto dal processo di login attuale.
     - **Verifica Soggetto**: Confronta il `subject` del token salvato in sessione con il `subject` del nuovo token.
     
5. **Esito della Verifica**:
   - **Soggetti Diversi $\to$ Errore**: Se i soggetti non coincidono, l'operazione è sospetta. Il filtro elimina il valore `MFA_FIRST_TOKEN` dalla sessione e lancia un'eccezione di autenticazione (redirect a errore).
   - **Soggetti Uguali $\to$ Successo**: Se i soggetti coincidono, l'utente ha superato entrambi i fattori per la stessa identità.

6. **Finalizzazione (Token Merge)**:
   Il sistema crea un nuovo `DefaultUserAuthenticationToken` che aggrega entrambi i token interni (`ExtendedAuthenticationToken`). L'utente ottiene l'accesso definitivo con un'identità supportata da due prove di autenticazione.

---

## 3. Mappa delle Classi di Riferimento

Per l'implementazione del PoC, le classi chiave da analizzare e utilizzare sono:

| Classe | Ruolo nel PoC | Cosa analizzare |
| :--- | :--- | :--- |
| `AbstractAuthenticationProcessingFilter` | **Base del Filtro** | Studiare come gestisce il redirect e l'intercettazione delle richieste di autenticazione. |
| `ConfirmKeyAuthenticationFilter` | **Esempio Implementativo** | Analizzare come estrae i dati di autenticazione e come interagisce con l' `AuthenticationManager`. |
| `DefaultUserAuthenticationToken` | **Contenitore Finale** | Utilizzare il costruttore che accetta un array di `UserAuthentication` per unire i due token di sessione. |
| `SecurityContextHolder` | **Gestore Stato** | Utilizzato per leggere e aggiornare l'autenticazione corrente durante il flusso. |

---

## 4. Roadmap di Sviluppo PoC

1. **Fase 1: Setup Filtro**: Creazione di `MfaPoCFilter` e inserimento nella `SecurityFilterChain` dopo i filtri di autenticazione standard.
2. **Fase 2: Gestione Sessione**: Implementazione della logica di salvataggio/recupero del primo token in `HttpSession`.
3. **Fase 3: Loop di Login**: Test del redirect forzato che obbliga l'utente a effettuare il login due volte (utilizzando l'IdP Password per semplicità di test).
4. **Fase 4: Validazione e Merge**: Implementazione del controllo del `subject` e creazione del `DefaultUserAuthenticationToken` finale contenente entrambi i token.