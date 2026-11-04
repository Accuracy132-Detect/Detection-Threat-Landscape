# Fake-download campaign: callback contract degli Inno offer

## 1. Scope and technical context

Il report analizza un solo comportamento della campagna pubblicata da Microsoft Security Research il 3 novembre 2026: le richieste di callback inviate dal delivery runner per comunicare il risultato di ciascuna offerta software. La fonte descrive deceptive installer presentati come cracked software, giochi, activator, plugin o utility non ufficiali; l'utente esegue il wrapper, che coordina più downstream offer nello stesso installer session [C001][S001]. La campagna è definita evolutiva, ma la fonte non fornisce date pubbliche di inizio e fine né un conteggio completo delle vittime [C011].

Il componente definito "Inno Setup-style wrapper" non prova una vulnerabilità di Inno Setup. Nel flusso osservato il wrapper usa directory temporanee come `%TEMP%\is-*.tmp`, avvia stage numerati e comunica con infrastruttura HTTP che ruota nel tempo [C002][C004]. Il comportamento coperto dalla query è più ristretto: un evento `DeviceNetworkEvents` nel quale `RemoteUrl` contiene insieme `d=inno` e uno dei valori `r=offer_execution` o `r=offer_execution_fail` [C003][C006][C007].

Il pacchetto non rileva direttamente l'esecuzione iniziale, il contenuto scaricato, una installation, un scheduled task o una forma di monetization. È una `Hunting query - Untested implementation sketch` con confidence `Medium`. Il match è un lead di sequenza da verificare con process, file, software-inventory e persistence evidence, non una decisione di compromissione [C008][C009][C013].

## 2. Technical mechanism and root cause

La condizione abilitante iniziale è l'esecuzione, da parte dell'utente, di un installer ottenuto da un canale ingannevole o non ufficiale [C001]. La fonte non stabilisce se ogni esecuzione derivi da advertising, search poisoning, redirect o altro delivery origin; questi elementi restano ignoti e non vengono sostituiti con una root cause inventata. Il confine di fiducia principale è l'accettazione di un installer non verificato, al quale l'identità dell'utente consente di avviare processi e stabilire connessioni di rete.

Nel wrapper, un runner temporaneo coordina independent offer. Le callback usano path randomizzati e parametri variabili, ma mantengono il delivery marker `d=inno` e un result marker `r=offer_execution` o `r=offer_execution_fail` [C003][C004]. Microsoft descrive questi callback come risultati per singola offerta: un fallimento non implica che l'intero bundle si arresti, e child payload possono essere avviati prima o vicino alla callback [C003][C013]. Di conseguenza, il parametro `r` non costituisce un reliable final verdict sulla sessione, né permette di dedurre l'esito di un'altra offerta.

La capacità ottenuta dal delivery system è la coordinazione di più software offer con reporting HTTP. La source-observed chain ha distribuito proxyware, distributed-compute components e utility-style software; una branch WorldProxyPool ha creato recurring scheduled task in contesto `SYSTEM` [C005]. Tuttavia, la query non osserva tali transizioni. Il match si colloca al confine tra endpoint e remote callback infrastructure e dimostra soltanto la presenza dei token nel campo URL acquisito da Microsoft Defender for Endpoint [C007][C008].

## 3. Timeline and execution flow

La precisione temporale disponibile è limitata. Microsoft ha pubblicato la ricerca il **3 novembre 2026**; questa analisi è del **4 novembre 2026**. La fonte parla di una campagna in evoluzione senza date pubbliche di prima osservazione, inizio o cessazione [C011][S001]. Non vi è patch timeline perché il report descrive software distribution abuse, non una CVE o un difetto accertato di Inno Setup.

La sequenza relativa supportata è:

1. **Deceptive delivery e user execution.** L'utente avvia un installer che si presenta come software desiderato ma non ufficiale [C001]. L'esecuzione è source-observed a livello di campagna; l'origine precisa del singolo installer resta ignota.
2. **Temporary staging.** L'Inno Setup-style wrapper usa un runner sotto `%TEMP%\is-*.tmp` e avvia stage numerati come `eld*.exe` o `set_*.exe` [C002]. Filename e path sono context di campagna, non condizioni della query.
3. **Per-offer coordination.** Il runner elabora una o più offer indipendenti. Il flusso può proseguire anche quando una offerta fallisce [C003]. Non è supportata una correlation window universale tra gli stage.
4. **Offer callback.** Il runner invia una richiesta HTTP con `d=inno` e un offer-result marker; domini e path possono ruotare mentre la coppia di token resta stabile [C003][C004]. Questa è l'unica transizione osservata dalla query.
5. **Downstream software behavior.** In alcune branch vengono avviati componenti di proxy o distributed computing, utility software o scheduled task [C005]. Poiché child payload possono partire prima o intorno alla callback, l'ordine puntuale e l'esito per ogni host devono essere ricostruiti dalla timeline locale [C013].

La fonte documenta attività riuscite nella campagna, ma un singolo match può rappresentare un tentativo, una callback di fallimento, una callback inviata dopo l'avvio di un child o un evento benigno con lessico coincidente. Senza eventi adiacenti, lo stato rimane ignoto [C008].

## 4. Impact and scope

L'impatto osservato dalla ricerca comprende tre modelli di monetization: uso della connettività tramite WorldProxyPool, distributed computing tramite CharityEngine/BOINC e installazione di utility-style software. Microsoft riferisce inoltre recurring `SYSTEM` scheduled task per WorldProxyPool [C005][S001]. Questi sono risultati source-observed della campagna, ma non sono dimostrati su ogni dispositivo e non sono outcome impliciti della callback.

L'impatto potenziale per un endpoint è l'uso non informato di network e compute resources, modifica della configurazione, persistence e privacy risk. Microsoft nota che alcuni prodotti downstream possono avere uso legittimo, mentre la silent installation tramite deceptive bundle, senza informed consent, crea il rischio [C012]. Non è supportato dedurre data theft, privilege escalation o total device control dalla sola logica pubblicata per questo observable.

L'ambito tecnico richiede un endpoint Windows coperto da Microsoft Defender for Endpoint e un evento in cui `RemoteUrl` conservi path e query parameters. La query non copre callback prive dei marker, protocolli o sensor path che non preservano il query string, endpoint non gestiti o varianti che usino un differente delivery contract. L'assenza di match non esclude la campagna; la presenza non prova installation o monetization [C008][C009].

## 5. Evidence and uncertainty

`S001` è la ricerca tecnica originale di Microsoft Security Research. Le sezioni sulla attack chain, Inno temp runner, callback lifecycle, downstream branch e official hunting query sostengono C001-C006, C011-C013. La fonte mostra la stabilità della coppia di marker su rotating infrastructure, ma non pubblica raw customer events, victim count, date complete o server-side semantics di tutti i parametri. Non attribuisce la campagna a un named threat actor.

`S002` documenta `DeviceNetworkEvents`, `RemoteUrl`, remote endpoint, initiating-process fields e la compound event identity basata su `Timestamp`, `DeviceName` e `ReportId` [C007]. La documentazione stabilisce lo schema disponibile, non garantisce che ogni network path conservi l'intero query string nel tenant target. `S004` e `S005` documentano la semantica Kusto di `has` e `has_any`; sostengono la sintassi, non l'interpretazione della campagna. `S003` sostiene soltanto il mapping T1071.001 per web protocol communication [C010].

C008 è l'inferenza che impone il confine di prova: confermarla richiede raw URL, process ancestry, download provenance e downstream artifacts; in loro assenza, il risultato resta callback-only. C009 è l'inferenza di deployment: positive e negative control devono confermare URL capture e specificità, mentre un historical review deve delimitare authorized bundler overlap. Query-string assente, single-marker control che matcha o prevalence non attribuibile smentiscono la suitability attuale.

La ricerca della campagna dipende da una sola indagine primaria. Schema e language reference sono ufficiali ma non indipendent incident corroboration. Non sono disponibili retained lab events, sample execution locale o target-environment prevalence. Queste lacune impediscono confidence `High` e giustificano le detrazioni dello score operativo.

## 6. Detection coverage and blind spots

La query nativa per Microsoft Defender XDR conserva i due filtri pubblicati da Microsoft: `RemoteUrl has "d=inno"` e `RemoteUrl has_any ("r=offer_execution", "r=offer_execution_fail")` [C006]. Non aggiunge IOC, domain list, threshold, rarity, aggregation, join, session parsing o arbitrary correlation window. Il portal time picker controlla l'intervallo. La projection estesa usa campi documentati per preservare device, remote endpoint, initiating process e compound event identity [C007].

Un risultato dimostra che MDE ha registrato un network event il cui `RemoteUrl` soddisfa entrambi i predicati. Non dimostra chi ha avviato l'installer, che il destination sia campaign-controlled, che il payload sia stato trasferito, che il risultato dichiarato dal callback sia attendibile, che una offerta sia stata installed o che il device sia compromised [C008][C013]. Il triage deve partire dalla raw event e da `InitiatingProcessUniqueId`, quindi ricostruire signer, download origin, process ancestry, file e software changes.

I blind spot includono URL truncation o normalization, proxy visibility diversa da endpoint visibility, encrypted connection priva del full URL, callback variant con altro vocabulary, process provenance incompleta, network event non acquisito e downstream execution fuori dalla finestra investigata. Authorized bundler, affiliate postback o security test possono produrre lessico coincidente. Per questi motivi il pacchetto resta `Hunting query - Untested implementation sketch` [C009].

## 7. Laboratory plan

Stato: **planned, not executed**. Non è registrata evidenza `dynamic-observed`, `exploit-reproduced` o `detection-validated`.

Il lab previsto usa una VM Windows 11 Enterprise isolata e organization-owned, collegata a un tenant Microsoft Defender for Endpoint non production, più un internal HTTP listener controllato. Devono essere registrati Windows build, Defender sensor version, proxy path, client version, test identity, DNS resolution e cloud-service health. Non vengono usati installer, domain, sample, credentials o downstream product della campagna.

Il positive control invia una sola harmless request a `dtl-inno-test.local` con `?d=inno&r=offer_execution&dtl_test=20261104`. I negative control inviano solo `d=inno`, solo `r=offer_execution`, eseguono un legitimate Inno Setup installer senza i marker e, se presente un proxy, confrontano la rappresentazione lungo lo stesso network path. Devono essere conservati listener log, raw `DeviceNetworkEvents`, process tree, query hash e UTC timeline [C009].

Success significa che la query invariata restituisce solo il paired-marker control, che `RemoteUrl` conserva semanticamente i token e che device, event identity e process context sono utilizzabili. Rejection significa URL incompleto, single-marker false match, required identity unusable o historical overlap non delimitabile. Sensor outage, routing esterno, telemetry delay o incomplete evidence sono failure inconclusivi. Il cleanup rimuove DNS/listener configuration e lab artifacts e conserva solo evidenza approvata. `validation.md` contiene i passaggi completi.

## 8. Analyst assessment and sources

La stable paired-marker structure è una detection opportunity fresca e più durevole dei rotating domain osservati nella campagna [C004]. Il valore operativo è alto perché Microsoft ha pubblicato direttamente la logica e lo schema Defender XDR è documentato, ma il significato del match rimane stretto: una callback per-offer può seguire l'avvio di un child e non rappresenta il final outcome dell'installer session [C006][C008][C013]. La decisione proporzionata è una `Hunting query` Medium-confidence con score operativo **44/51**, non una production alert.

La prossima verifica utile è il controlled URL-capture test con negative controls, seguita da historical prevalence review. Aggiungere process name, domain, stage filename, threshold o timing senza evidenza ridurrebbe la difendibilità. Se il query string non è acquisito o l'overlap benigno non è delimitabile, il hunt deve essere ridisegnato o ritirato; se i controlli riescono, si può valutare alert logic soltanto con una corroborating endpoint primitive.

Fonti aperte e verificate: Microsoft Security Research `S001`, Microsoft Defender XDR schema `S002`, MITRE ATT&CK `S003`, Kusto operator references `S004` e `S005`. I claim sono nel ledger `evidence.json`; provenance e date in `references.json`; il piano in `validation.md`; la query completa in `hunting.kql`. Il PDF canonico riassume autonomamente condizioni, meccanismo, sequenza, impatto, evidence boundary, detection e laboratorio.
