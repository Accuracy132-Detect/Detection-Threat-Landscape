# SlippyNunchucks: hijack del componente promozionale Sogou e side-loading DarkVigil

## 1. Scope and technical context

Questo report analizza la campagna pubblicata da ESET Research il **4 novembre 2026** e osservata a partire dal **1 luglio 2026**, nella quale il workflow di brand promotion di Sogou Input Method è stato deviato verso una configurazione controllata dall'attaccante [C001][S001]. La fonte attribuisce l'operazione al cluster China-aligned SlippyNunchucks e riferisce organizzazioni e utenti sinofoni interessati in Hong Kong, Thailandia, Giappone, Vietnam, Sri Lanka e Oman [C002]. Il conteggio complessivo delle vittime, la data di cessazione e il punto esatto della manipolazione DNS non sono pubblici.

Il software normale usa `SGTool.exe` per recuperare una configurazione di brand promotion. Nelle versioni interessate la richiesta avveniva su HTTP non cifrato; la configurazione restava cifrata, ma la risoluzione controllata dall'attaccante conduceva a un server capace di restituire un oggetto cifrato accettato dal client [C003]. La versione 16.10 ha spostato il percorso su HTTPS con certificate pinning; ESET colloca il confine di remediation tra il 29 e il 30 ottobre 2026 e assegna CVE-2026-120422 [C007].

La detection non ricostruisce l'intera catena. Copre soltanto l'evento endpoint in cui un processo `SogouComMgr.exe`, con company metadata Adobe, carica un `libcef.dll` co-locato sotto un path `SogouInput\Components` [C005][C008][C009]. È una `Hunting query - Untested implementation sketch` con confidence `Medium`; non è un verdict di compromissione.

## 2. Technical mechanism and root cause

La condizione abilitante documentata è l'uso di HTTP senza protezione di trasporto per la richiesta di configurazione di `SGTool.exe`, combinato con la capacità dell'attaccante di influenzare la risoluzione DNS o il traffico di rete della vittima [C003]. La cifratura applicativa della configurazione non autenticava in modo sufficiente l'origine del canale: il server di staging restituiva una configurazione cifrata che modificava hash e destination field usati dal client per scaricare componenti. ESET non ha stabilito se la manipolazione avvenisse sul dispositivo, nel resolver, nell'ISP o in un altro segmento; questa lacuna impedisce una root cause infrastrutturale più precisa.

La configurazione malevola ordinava a `SGTool.exe` di recuperare un legittimo Adobe Licensing WF Helper e un `libcef.dll` identificato da ESET come DarkVigil [C004]. Il helper veniva salvato con l'identità Sogou `SogouComMgr.exe`, mentre il DLL veniva collocato accanto all'eseguibile sotto `SogouInput\Components` o in una directory versionata `Components\biz_center` [C005][C006]. Quando il workflow di component management avviava il helper rinominato, il normale meccanismo di ricerca DLL caricava il `libcef.dll` co-locato [C005].

Il confine di fiducia attraversato è doppio: il client Sogou accetta una configurazione proveniente da un canale di trasporto manipolabile e poi avvia un componente apparentemente Sogou che conserva metadata Adobe. Il helper opera con i privilegi dell'identità che esegue il workflow; la fonte non dimostra un privilege escalation. La query utilizza l'incongruenza di identità e la relazione di caricamento, ma non inferisce una firma valida dai version fields né attribuisce il contenuto del DLL [C009][C010].

## 3. Timeline and execution flow

La sequenza temporale supportata è distinta dalla publication date:

1. **1 luglio 2026 — first observed activity.** ESET osserva DarkVigil avviato dal componente Sogou `SGTool.exe` [C001]. La fonte non pubblica l'ora, il fuso o la prima preparazione dell'infrastruttura.
2. **Pre-16.10 enabling condition.** Il client invia la richiesta di configurazione di brand promotion su HTTP; la risoluzione controllata conduce al server di staging [C003][C007]. Il punto di interception resta ignoto.
3. **Configuration injection.** Il server risponde con una configurazione cifrata malevola, accettata dal client, che sostituisce gli indicatori di integrità e i path di destinazione [C003][C004]. Questo passaggio è source-observed nella campagna, non osservato dalla query.
4. **Component placement.** `SGTool.exe` scarica il helper Adobe e `libcef.dll`, rinomina il primo `SogouComMgr.exe` e dispone entrambi nella stessa component directory [C004][C005]. ESET documenta un secondo workflow in `biz_center`; i due workflow non sono simultanei [C006].
5. **Masqueraded execution and DLL load.** Il component-management workflow avvia `SogouComMgr.exe`; il helper carica il DLL co-locato [C005][C008]. Solo questa transizione è rappresentata dal hunt.
6. **Downstream implant behavior.** ESET identifica il DLL come DarkVigil e descrive un framework DMTP capace di ricevere plugin e raccogliere dati [C012]. Un match non stabilisce che queste capacità siano state eseguite.
7. **11 settembre 2026 — coordinated disclosure.** ESET comunica il problema a Tencent [C007].
8. **29-30 ottobre 2026 — remediation boundary.** La versione 16.10 introduce HTTPS e certificate pinning; la fonte usa entrambe le date in passaggi diversi, quindi il report conserva il range anziché scegliere una precisione non supportata [C007].
9. **4 novembre 2026 — publication.** ESET pubblica l'indagine; questo pacchetto è del 5 novembre 2026 [C001].

Le transizioni 3-6 sono descritte come riuscite negli ambienti investigati. Su un singolo endpoint, tuttavia, la query può documentare soltanto il load event; download, origine, contenuto, riuscita dell'impianto e attività successiva richiedono artefatti indipendenti [C009].

## 4. Impact and scope

L'impatto osservato è l'esecuzione di DarkVigil attraverso un workflow di update/promozione di software legittimo, con possibilità di plugin delivery e data collection descritte da ESET [C002][C012]. La fonte riferisce un insieme geografico di vittime ma non un numero completo, una percentuale di installazioni esposte o una conferma che ogni host abbia eseguito tutte le capability [C002]. Per questo motivo il report distingue delivery riuscita, capacità potenziale e attività effettivamente attribuibile a ciascun dispositivo.

La superficie nota comprende installazioni Windows di Sogou Input Method precedenti alla 16.10 che usano il percorso HTTP interessato e che si trovano in una posizione di rete dove la risoluzione o il traffico può essere manipolato [C003][C007]. Installare la 16.10 riduce la condizione abilitante descritta tramite HTTPS e certificate pinning, ma l'inventario di versione non prova né esclude una compromissione precedente. Un endpoint già contenente file o persistence richiede incident response separata.

Il potenziale impatto include esecuzione di codice nel contesto del workflow, plugin aggiuntivi e raccolta di dati, ma il query match non dimostra nessuno di questi outcome. Non dimostra privilege escalation, lateral movement, data exfiltration, command success o attribuzione. `DeviceImageLoadEvents` espone una primitive di hunting sull'identità e sul module load, non il contenuto o l'intento del file [C008][C009].

## 5. Evidence and uncertainty

`S001` è l'unica indagine primaria della campagna ed espone date, architettura del workflow, DNS hijack osservato, configurazione, file placement, due execution workflow, impatto e remediation. Sostiene C001-C007 e C012, ma non pubblica raw customer events, victim count completo, punto di manipolazione DNS o campaign end. L'attribuzione SlippyNunchucks e l'identificazione DarkVigil sono interpretazioni ESET basate sulla propria indagine [C002][C012]; il pacchetto le conserva come source facts, non come risultati della query.

`S002` documenta `DeviceImageLoadEvents`, il prerequisito Microsoft Defender for Endpoint e i campi module, path, initiating process, version metadata, hash, `InitiatingProcessUniqueId` e compound event identity usati o proiettati [C008]. La documentazione stabilisce la semantica dello schema, non garantisce la raccolta per ogni host né l'affidabilità dei version resources. `S005` documenta `=~` e `has`; sostiene la sintassi, non l'interpretazione della campagna [C013]. `S003` e `S004` sostengono soltanto T1574.001 e T1036.005 [C011].

C009 definisce il confine di prova: confermarlo richiede evento raw, raccolta dei due file, hash, certificate record, versione Sogou, installer provenance e correlazione con `SGTool.exe`, DNS, HTTP, registry e network evidence. C010 è l'inferenza di deployment: positive e negative controls devono dimostrare image-load coverage, metadata population e specificità; prevalence non attribuibile, metadata null o false negative la smentiscono. Le assunzioni residue sono che MDE registri il load e che authorized software non replichi normalmente l'intera identità incrociata.

La fonte contiene una discrepanza interna fra 29 e 30 ottobre per la remediation 16.10. Non viene normalizzata silenziosamente: il range è mantenuto in report e ledger. Il lab non è stato eseguito, quindi non esiste evidenza `dynamic-observed`, `detection-validated` o di target-environment prevalence.

## 6. Detection coverage and blind spots

La query nativa Microsoft Defender XDR filtra un singolo `DeviceImageLoadEvents` event. Richiede `libcef.dll`, i termini `SogouInput` e `Components` nel module path, `SogouComMgr.exe` come initiating process, gli stessi termini nel process path, uguaglianza case-insensitive fra le due directory e `Adobe` nel company metadata [C005][C008][C013]. Non usa hash, IOC di rete, threshold, count, rarity, sequence, join o correlation window. La scelta preserva una relazione source-observed e investigabile senza affermare eventi non raccolti.

Il match dimostra che Defender ha registrato la relazione loader-module-path-company metadata. Non dimostra che il company metadata sia autentico o firmato, che il DLL sia malevolo, che sia DarkVigil, che la richiesta HTTP sia stata deviata, che CVE-2026-120422 sia stata sfruttata, che l'host sia compromised o che SlippyNunchucks sia responsabile [C009]. Il triage deve preservare l'event identity, raccogliere i file, verificare certificate chain e provenance, controllare la versione Sogou e ricostruire la timeline adiacente.

I blind spot includono un loader rinominato diversamente, alternate module name, path non contenente i token, file non co-locati, metadata modificato o assente, image-load telemetry non acquisita e una variante che non usa il helper Adobe. Authorized research, packaging o test possono riprodurre la relazione. La hunt resta quindi `Medium` e non può essere promossa senza i controlli descritti in `validation.md` [C010].

## 7. Laboratory plan

Stato: **planned, not executed**. Non sono registrati risultati dinamici o validazione della detection.

Il lab usa una VM Windows 11 Enterprise isolata, organization-owned e collegata a un tenant Microsoft Defender for Endpoint non production. Devono essere registrati Windows build, Defender sensor version, test identity, cloud-service health, sorgente/build del loader e del no-op DLL, file hashes e version resources. Non si usano Sogou, campioni, hash, domini o infrastrutture della campagna; non si manipolano DNS e non si crea persistence.

Il positive control colloca un benign loader interno come `C:\DTL-Lab\SogouInput\Components\SogouComMgr.exe`, con synthetic test company metadata contenente `Adobe`, accanto a un `libcef.dll` no-op e genera un solo load. I negative controls modificano separatamente company metadata, module name e path; un legitimate CEF load verifica l'overlap ordinario. Devono essere conservati raw event, build manifest, hashes, query hash e UTC timeline [C008][C010].

Success significa che la query invariata restituisce il positive con context completo, esclude ogni semantic negative per la ragione prevista e produce prevalence storica delimitabile. Rejection significa load assente, metadata null/incoerente, folder equality inaffidabile, negative match o benign overlap non separabile. Sensor outage, stale policy, telemetry delay o evidence loss sono failure inconclusivi. Il cleanup elimina gli artefatti, ripristina la VM e conserva soltanto evidenza approvata. `validation.md` contiene la procedura completa.

## 8. Analyst assessment and sources

Il comportamento offre un'opportunità operativa concreta perché combina un module load documentato, una directory Sogou e un'identità file che conserva metadata Adobe. La relazione è più specifica di filename, path o company metadata presi singolarmente e usa uno schema ufficiale senza threshold o correlazione artificiale [C005][C008][C010]. Tuttavia, dipende da una singola indagine primaria, da artefatti mutabili e da field completeness non misurata; la decisione proporzionata è `Hunting query` Medium-confidence con score operativo **43/51**, non un alert.

La priorità successiva è il controlled image-load test, seguito da historical prevalence e file-provenance review. Se i campi non sono popolati o l'overlap non è delimitabile, la query deve essere ridisegnata o ritirata; se i controlli riescono, l'eventuale promotion richiede almeno una corroborating primitive indipendente. Non si deve aggiungere una domain list, un hash, una parent condition, un threshold o un timing non supportato.

Fonti aperte e verificate: ESET Research `S001`, Microsoft Defender XDR schema `S002`, MITRE ATT&CK `S003` e `S004`, Kusto string operators `S005`. I claim sono nel ledger `evidence.json`; provenance e date in `references.json`; il piano in `validation.md`; la query completa in `hunting.kql`. Il PDF canonico riassume autonomamente condizioni, meccanismo, sequenza, impatto, evidence boundary, detection e laboratory plan.
