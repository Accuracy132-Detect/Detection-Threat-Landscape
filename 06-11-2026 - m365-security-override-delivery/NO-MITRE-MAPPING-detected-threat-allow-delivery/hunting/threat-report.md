# Microsoft 365: threat verdict consegnati attraverso allow override

## 1. Scope and technical context

Questo report analizza il comportamento pubblicato da Microsoft Threat Intelligence e Microsoft Defender Security Research Team il **5 novembre 2026**, sulla base di telemetria email osservata tra **luglio e settembre 2026** [C001][S001]. Il report sorgente descrive circa 7,3 miliardi di phishing threat nel trimestre e, nel sottoinsieme pertinente a questo pacchetto, circa **129 milioni** di messaggi malevoli che dichiaravano come sender domain servizi business noti [C002]. Il dato riguarda detection Microsoft; non equivale a un conteggio di messaggi letti, account compromessi o incidenti riusciti.

Il comportamento normale di Microsoft 365 combina verdict del filtering stack, policy organizzative o di mailbox e un'azione di consegna. Un'eccezione può essere necessaria per mantenere un workflow legittimo; se troppo ampia o non più necessaria, può però neutralizzare un segnale di sicurezza. Microsoft documenta `EmailEvents` come lo schema nativo che rappresenta verdict, override e delivery [C004][C005][S002][S003].

La detection copre esclusivamente il control outcome: inbound mail, `ThreatTypes` non vuoto, `OrgLevelAction` oppure `UserLevelAction` uguale a `Allow`, e `DeliveryAction` uguale a `Delivered` [C005][C006]. È una `Hunting query - Untested implementation sketch`, confidence `Medium`. Non analizza body, attachment, URL o payload e non dimostra recipient interaction.

## 2. Technical mechanism and root cause

La condizione abilitante non è una vulnerabilità software dimostrata. È una configurazione di trust: una policy definita dall'organizzazione o dall'utente può applicare un'azione `Allow` a un messaggio che il filtering stack ha già classificato con un threat verdict [C004][C006]. Microsoft afferma che gli attacker sfruttano questi gap e che allow entry non necessarie costituiscono un rischio; nel campione Q3, molti messaggi identificati come malevoli e con authentication check falliti sono stati consegnati perché eccezioni configurate hanno prevalso [C002].

Il flusso attraversa tre componenti logici. Il filtering stack elabora il messaggio e valorizza `ThreatTypes`; il policy engine applica `OrgLevelAction` o `UserLevelAction`; il delivery pipeline registra `DeliveryAction` [C005]. La query richiede la coesistenza dei tre stati sullo stesso evento email e limita l'input a `EmailDirection == "Inbound"`. `NetworkMessageId` e `RecipientEmailAddress` consentono il pivot investigativo, ma non vengono usati per una correlazione artificiale.

La root cause del singolo match può essere un allow entry intenzionale ma troppo ampia, una mailbox safe-sender policy, un test, una falsa detection o una configurazione obsoleta. Il report pubblico non espone policy ID, tenant o raw row del campione aggregato; pertanto non è possibile attribuire una causa unica a tutti i risultati. L'attaccante non deve necessariamente modificare la policy: può semplicemente inviare un messaggio che beneficia di un'eccezione preesistente. La query non assume che `AuthenticationDetails` contenga un fallimento e lo proietta solo per triage [C007].

## 3. Timeline and execution flow

La cronologia supportata deve distinguere observation period e publication date:

1. **Luglio-settembre 2026 — observation period.** Microsoft raccoglie e analizza la telemetria email Q3 [C001]. L'ora e il tenant di ciascun evento non sono pubblici.
2. **Q3 2026 — attacker delivery.** Messaggi inbound dichiarano sender domain di servizi business familiari; Microsoft ne conta circa 129 milioni nel perimetro analizzato [C002]. La query non richiede quel brand o quella forma di spoofing.
3. **Per-message filtering.** Il filtering stack assegna un threat verdict. La hunt osserva soltanto che `ThreatTypes` non è vuoto [C005][C006]. Non deduce il valore di `AuthenticationDetails`.
4. **Policy transition.** Una policy organizzativa o utente registra `Allow` [C003][C004][C006]. Nel settembre 2026, gli override rappresentano il 63% dei messaggi studiati con recorded security outcome; la maggioranza è tenant-level [C003].
5. **Initial delivery.** `DeliveryAction` è `Delivered` [C005][C007]. La query proietta `LatestDeliveryAction` e `LatestDeliveryLocation`, ma non presume che il messaggio sia ancora accessibile [C009].
6. **Downstream outcome.** Apertura, click, credential entry, code execution e account compromise restano ignoti e richiedono telemetria indipendente [C007].
7. **5 novembre 2026 — publication.** Microsoft pubblica l'analisi; il pacchetto è datato 6 novembre 2026 [C001].

La sequenza 3-5 è il solo confine coperto. Un risultato documenta un override realizzato e una consegna iniziale, non l'intera intrusione. La sorgente distingue esplicitamente delivery da apertura o compromissione [C002][C007].

## 4. Impact and scope

L'impatto osservato è la consegna di messaggi che avevano ricevuto un threat verdict nonostante i controlli, per effetto di eccezioni organizzative o utente [C002][C003]. Questo è già un control failure operativo: la policy ha trasformato una detection in delivery. Il report Microsoft non stabilisce quanti recipient abbiano letto il messaggio, quanti abbiano interagito o quanti account siano stati compromessi; tali outcome non devono essere derivati dall'aggregato.

L'impatto potenziale dipende dal contenuto del singolo messaggio. La ricerca Q3 descrive phishing, credential theft e malware delivery, ma la query non restringe `ThreatTypes` a una categoria, non ispeziona attachment o URL e non associa un actor o campaign. Per questo non riceve un mapping MITRE ATT&CK: il match è un control outcome generico, non una specifica tecnica di delivery o accesso [C010].

La superficie riguarda tenant con Microsoft Defender for Office 365 e allow policy organizzative o mailbox. L'esposizione è ampia per organizzazioni Microsoft 365, ma la visibilità richiede Plan 2 e populated fields [C004][C005]. Un messaggio può essere rimosso dopo la consegna da Zero-hour auto purge o da un analyst; iniziale delivery e current exposure sono stati distinti [C009].

## 5. Evidence and uncertainty

`S001` è ricerca Microsoft originale su telemetria Q3. Sostiene date, quantità, override distribution e il confine secondo cui delivery non prova interaction o compromise [C001][C002][C003]. La fonte è vicina all'osservazione ma non pubblica raw `EmailEvents`, tenant, policy scope o percentuale di downstream compromise. I numeri sono vendor measurements e non vengono generalizzati a ogni ambiente.

`S002` documenta `EmailEvents`, i valori `Inbound` e `Delivered`, la semantica dei verdict, le azioni organizzative/utente, le policy, gli identificatori e i campi latest state [C005]. La documentazione stabilisce schema e valori, non garantisce field completeness nel tenant. `S003` documenta il pattern `OrgLevelAction == "Allow" and ThreatTypes != ""`, la sostituzione con `UserLevelAction` e il prerequisito Plan 2 [C004][C006].

C007 definisce il confine di prova e può essere confermato solo preservando il raw row, aprendo la message entity, verificando policy e current state e correlando click, sign-in ed endpoint evidence. C008 è l'inferenza di operatività: prevalence e ownership delimitate la supportano; field gap o overlap non attribuibile la smentiscono. C009 impedisce di confondere delivery iniziale con presenza corrente. C010 conserva l'assenza di mapping ATT&CK finché una condizione ulteriore non rappresenta una tecnica specifica.

Il laboratorio non è stato eseguito. Non esiste evidenza `dynamic-observed`, `detection-validated` o di target-environment performance. La dipendenza da un solo vendor è compensata solo dalla documentazione ufficiale dello stesso prodotto, non da corroborazione indipendente della statistica.

## 6. Detection coverage and blind spots

La query nativa Microsoft Defender XDR filtra una singola tabella `EmailEvents`. Richiede `EmailDirection == "Inbound"`, `ThreatTypes != ""`, almeno uno tra `OrgLevelAction` e `UserLevelAction` uguale a `Allow`, e `DeliveryAction == "Delivered"` [C005][C006]. Non usa IOC, domain list, attachment name, threshold, baseline, join, sequence, parsing di JSON, rarity o inferred authentication failure.

Un match dimostra soltanto il quadruplo stato registrato sullo stesso recipient/message event [C007]. `OrgLevelPolicy` e `UserLevelPolicy` aiutano ad attribuire la decisione; `AuthenticationDetails`, `DetectionMethods` e `ConfidenceLevel` spiegano il contesto; i latest fields aiutano a stabilire remediation successiva. Nessuno di questi enrichment prova che il recipient abbia visto o usato il contenuto.

I blind spot includono messaggi non rilevati, eccezioni non rappresentate dai campi documentati, tenant senza Plan 2, campi null, mail flow esterno a Microsoft 365 e post-delivery events non conservati. Benign overlap comprende false-positive verdict, vendor exception necessarie e approved simulations. Stale o broad allow entries non sono false positive della hunt: sono il control gap che la hunt deve rendere visibile [C008].

## 7. Laboratory plan

Stato: **planned, not executed**. La validazione usa un tenant Microsoft 365 isolato, organization-owned, senza production recipient o forwarding, con Microsoft Defender for Office 365 Plan 2. Devono essere registrati tenant, service health, policy version, test identities, raw `EmailEvents`, policy audit record, message entity, query hash e UTC timeline.

Prima del test attivo si esegue una review passiva di 30 giorni e si assegna ogni risultato a policy owner, business justification e disposition. Il positive control crea un allow entry temporaneo e strettamente scoped, poi invia una sola Microsoft-supported harmless simulation già verificata in blocked delivery come capace di popolare `ThreatTypes`. Se il simulation path produce telemetria speciale, non è valido e il pacchetto resta hunting [C008].

I controlli negativi sono: benign mail consentita con `ThreatTypes` vuoto; simulated threat senza allow; e, solo se sicuro e supportato, detected/allowed mail non delivered. Il successo richiede positive completo, negative esclusi per la condizione prevista e overlap storico delimitato. Rejection scatta con required field mancanti, simulation semantics non rappresentative o policy ownership non recuperabile. Failure include unsafe content, accidental production routing, rollback failure o evidence loss. Il cleanup elimina l'allow entry, purga i messaggi e verifica la baseline. `validation.md` conserva procedura, expected artifacts e criteri completi.

## 8. Analyst assessment and sources

La primitiva è operativamente utile perché collega verdict, exception e delivery sul singolo messaggio senza dedurre body o outcome. È più concreta di un inventario allowlist e più investigabile di un trend aggregato. Lo schema è documentato, i valori sono usati dalla guida ufficiale e non servono threshold arbitrari [C004][C005][C006]. Il punteggio operativo è **45/51**: le detrazioni riguardano singola indagine vendor, benign overlap tenant-specific e laboratorio non eseguito.

La decisione proporzionata è `Hunting query`, confidence `Medium`, non alert. La priorità è misurare prevalence e policy ownership, quindi eseguire il controllo harmless in tenant isolato. Se i campi non sono completi o le eccezioni necessarie non sono separabili, la hunt deve restare investigativa o essere ritirata. Un risultato non autorizza da solo purge, account reset o incident declaration [C007][C008][C009].

Fonti aperte e verificate: Microsoft Threat Intelligence `S001`, schema `EmailEvents` `S002`, allowlist review guidance `S003`. I claim sono in `evidence.json`; provenance e date in `references.json`; il piano in `validation.md`; la query completa in `hunting.kql`. Il PDF canonico riassume in modo autonomo condizioni, meccanismo, sequenza, impatto, evidence boundary, detection e laboratory plan.
