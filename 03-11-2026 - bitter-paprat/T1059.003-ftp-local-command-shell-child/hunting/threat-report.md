# BITTER / PapRAT: abuso di ftp.exe per l'esecuzione di una shell locale

## 1. Scope and technical context

Il presente report analizza esclusivamente la prima delle tre infection chain descritte da FortiGuard Labs il 2 novembre 2026. La fonte riferisce di una campagna attribuita dal vendor a BITTER, osservata per diversi mesi contro organizzazioni dell'Asia meridionale, e separa una catena basata su `ftp.exe` da due catene distinte che installano PapRAT tramite VHDX/LNK/MSI o URL/WebDAV/MSI [C001][C010][S001]. Questa separazione è essenziale: la detection proposta non copre PapRAT, WmRAT, MSI execution, WebDAV, C2 o le capacità del RAT.

Nel comportamento normale, il client FTP nativo di Windows interpreta direttive di sessione. La documentazione Microsoft descrive però il comando `!`, applicabile nelle versioni legacy elencate dalla pagina, come una transizione temporanea dal sottosistema FTP a un command prompt locale dal quale possono essere eseguiti comandi del sistema operativo [C004][S003]. FortiGuard Labs documenta che l'attaccante ha utilizzato questa possibilità tramite un LNK che avvia `ftp.exe` e uno script: `!more res.ico` legge il contenuto locale di `res.ico` e lo inoltra a `cmd.exe` [C002][S001].

Il perimetro operativo del pacchetto è quindi una sola process primitive: `cmd.exe` creato direttamente da `ftp.exe` in `DeviceProcessEvents`. Il pacchetto non tratta un match come prova dell'intera intrusione. Lo scopo è ottenere un lead investigativo durevole rispetto a filename, domini e hash di campagna, mantenendo la classificazione `Hunting query` e la confidence `Medium` finché la rappresentazione EDR non viene riprodotta [C006][C007][C009].

## 2. Technical mechanism and root cause

La condizione abilitante documentata comprende due passaggi. Primo, un utente o processo deve eseguire il LNK malevolo; FortiGuard Labs non espone il vettore di consegna iniziale né la specifica interazione della vittima, perciò non è possibile descrivere una root cause di delivery senza inventarla [C001][S001]. Secondo, il contenuto controllato dall'attaccante viene interpretato dal client FTP e usa la funzione `!` per attraversare il confine tra la grammatica FTP e l'esecuzione locale di comandi [C002][C004].

Il meccanismo non è una vulnerabilità di memoria né un exploit con esito implicito. È abuso di una funzionalità documentata: Microsoft afferma che `!` apre temporaneamente un command prompt, mentre FortiGuard Labs mostra l'uso di `!more res.ico` e il pipe verso `cmd.exe` nella catena osservata [C002][C004]. I privilegi ottenuti sono quelli del processo e dell'identità che avviano il LNK/FTP; la fonte non dimostra elevation in questo passaggio. Il confine di fiducia è il passaggio da istruzioni memorizzate in un file di input controllato dall'attaccante a un command shell locale.

L'inferenza di detection è che la transizione produca una relazione diretta `ftp.exe` → `cmd.exe` in Microsoft Defender for Endpoint [C006]. Microsoft documenta `DeviceProcessEvents` come telemetria di process creation e documenta `FileName`, `InitiatingProcessFileName`, i command line fields, i process unique IDs e la compound event identity basata su `Timestamp`, `DeviceName` e `ReportId` [C005][S002]. Tuttavia, nessun raw event della campagna o laboratorio autorizzato è disponibile. La relazione EDR è quindi una previsione falsificabile, non un fatto osservato nel tenant.

## 3. Timeline and execution flow

La precisione temporale disponibile è limitata. FortiGuard Labs ha pubblicato la ricerca il 2 novembre 2026 e dichiara di avere seguito la campagna nei mesi precedenti, senza indicare data iniziale, data finale o timezone degli eventi [C010][S001]. L'analisi e la stesura del pacchetto sono del 3 novembre 2026. Non sono riportate date di patch perché il comportamento usa una funzione documentata e non viene presentato come CVE.

La sequenza relativa supportata per chain 1 è la seguente:

1. **Execution del LNK:** il collegamento richiama `ftp.exe` con contenuto script associato a `icon.ico` [C001][C002]. È documentato l'avvio della catena; il delivery origin è ignoto.
2. **Local shell transition:** il token `!` fa eseguire un comando locale; `!more res.ico` legge il file e passa il contenuto a `cmd.exe` [C002][C004]. La funzione è documentata e l'uso malevolo è source-observed; la rappresentazione EDR resta inferred [C006].
3. **Command interpretation:** `cmd.exe` interpreta le istruzioni contenute in `res.ico`. La query cerca soltanto la relazione di processo di questo passaggio e non può provare il contenuto del file [C006][C007].
4. **Persistence e retrieval:** gli script source-observed creano scheduled task, avviano `conhost --headless cmd /c more ... | cmd` e usano `curl` per recuperare comandi [C003]. Questi eventi sono enrichment, non condizioni della query.
5. **Discovery e transfer:** almeno un ramo raccoglie directory listing, task list, antivirus product data e drive information in `abc.pdf`, poi invia il file al server remoto e lo elimina [C003]. La fonte documenta il comando; un match del hunt non dimostra né la riuscita dell'upload né l'impatto sul singolo host [C007].

Le chain 2 e 3 introducono MSI/PapRAT e capacità RAT, ma non possono essere unite causalmente a un match `ftp.exe` → `cmd.exe`. La chain 3 riutilizza elementi delle prime due; resta comunque fuori scope per evitare che un singolo observable venga sovrainterpretato.

## 4. Impact and scope

L'impatto osservato dichiarato da FortiGuard Labs per la campagna comprende controllo dei sistemi compromessi. Per la sola chain 1, la fonte pubblica comandi di scheduled-task persistence, retrieval remoto, reconnaissance e upload di dati raccolti [C003][S001]. Il materiale sostiene l'esistenza delle operazioni nella catena analizzata, ma non fornisce un conteggio di vittime, una conferma per ogni host, l'esito server-side di ogni upload o un inventario completo dei dati sottratti.

L'impatto potenziale della primitive è l'esecuzione di comandi con il token dell'utente o processo che avvia `ftp.exe`, seguita da persistence, collection e network transfer se gli stadi successivi vengono eseguiti con successo. Non è supportata un'inferenza di privilege escalation. Non è inoltre corretto trasferire automaticamente al chain 1 tutte le capacità di PapRAT descritte per le altre chain.

L'ambito tecnico è Windows con `ftp.exe` disponibile e telemetry di Microsoft Defender for Endpoint. La pagina Microsoft sul comando `!` dichiara versioni fino a Windows 8 e Windows Server 2012 [C004][S003]; FortiGuard Labs documenta la primitive in una campagna moderna, ma il comportamento deve essere confermato sulla build effettivamente gestita. La presenza di `ftp.exe` o di un LNK non equivale a compromissione, e l'assenza di un match non esclude varianti che usino un altro shell, un intermediario diverso o telemetry non raccolta.

## 5. Evidence and uncertainty

`S001` è ricerca tecnica originale di FortiGuard Labs. Le sezioni Attack Chain 1 e Conclusion sostengono la separazione delle chain [C001], l'uso di `!more res.ico` e `cmd.exe` [C002], e gli stadi di scheduled task, `curl`, reconnaissance e upload [C003]. L'attribuzione a BITTER è un'interpretazione ad alta confidence del vendor basata, secondo la fonte, su lure filenames, C2 patterns, metadata e malware analysis; non è stata verificata indipendentemente e non entra nella query [C011].

`S003` documenta la semantica del comando FTP `!` [C004], ma è una pagina legacy con version scope esplicito. `S002` documenta lo schema `DeviceProcessEvents` e i campi usati [C005], ma non dimostra che il particolare shell escape generi la parent-child lineage proposta. `S004` sostiene soltanto il mapping T1059.003 [C008].

La principale inferenza è C006: `cmd.exe` dovrebbe essere registrato con `ftp.exe` come initiating process. Essa sarà confermata o smentita mediante un positive control innocuo su una build Windows corrente, con raw process tree conservato. C009 stabilisce che la promozione dipende da field completeness e benign prevalence; sarà smentita come candidato di alert se la lineage è instabile o l'overlap è non delimitabile. C007 impone il confine interpretativo: un match non rivela il contenuto del file FTP né dimostra campagna, malware o impatto.

Questa analisi dipende da una sola indagine primaria per il comportamento di campagna. Non sono disponibili raw EDR events, sample execution locale, network capture o una seconda incident source indipendente. Queste lacune motivano le detrazioni nello score operativo e impediscono confidence High.

## 6. Detection coverage and blind spots

La query nativa per Microsoft Defender XDR usa due soli predicati documentati: `FileName =~ "cmd.exe"` e `InitiatingProcessFileName =~ "ftp.exe"`. Non contiene IOC, threshold, rarity, aggregation, join o correlation window. Il time range resta sotto il controllo dell'operatore nel portal. I campi projected preservano device, account, command line, path, hash, stable process IDs e compound event identity per il triage [C005][C006].

Un risultato dimostra unicamente la rappresentazione `ftp.exe` → `cmd.exe` in `DeviceProcessEvents` [C007]. Non dimostra che il parent abbia letto `icon.ico` o `res.ico`, che il token `!` fosse presente, che il child abbia eseguito contenuto malevolo o che scheduled task, `curl`, C2, discovery o upload siano avvenuti. L'associazione a BITTER o PapRAT richiede evidenza indipendente [C011].

I blind spot comprendono: shell diverso da `cmd.exe`; processo intermediario; telemetry assente o ritardata; sensor che normalizza ancestry diversamente; process command line non popolata; esecuzione su endpoint non coperti; e varianti delle altre infection chain che non usano questa primitive. Le automazioni FTP legacy che invocano comandi locali possono produrre overlap legittimo. Per questo il pacchetto resta `Hunting query - Untested implementation sketch` [C009].

## 7. Laboratory plan

Stato: **planned, not executed**. Nessuna evidenza `dynamic-observed`, `exploit-reproduced` o `detection-validated` è registrata.

L'ambiente previsto è una VM Windows 11 Enterprise isolata, autorizzata e connessa a un tenant Microsoft Defender for Endpoint non production. Prima del test devono essere registrati exact Windows build, Defender sensor version, cloud health, test account e baseline `DeviceProcessEvents`. Non verranno usati sample, IOC, credential o infrastructure della campagna.

Il positive control usa un file locale per `ftp.exe` contenente un comando `!` innocuo che richiama `cmd.exe /c` e crea esclusivamente `%TEMP%\DTL_FTP_SHELL_TEST.txt`. Devono essere conservati command file, command line, marker hash, raw process events e process tree. I negative control sono: FTP script senza `!`; stesso comando innocuo avviato da `powershell.exe`; sessione FTP transfer-only. Soltanto il positive control deve soddisfare entrambi i filtri [C006][C009].

Success significa una lineage diretta, completa e ripetibile, required fields popolati e assenza di match per i controlli negativi. Rejection significa ancestry diversa, required fields mancanti, negative controls che matchano o overlap legittimo non delimitabile. Sensor outage, errore del command file, ritardo oltre retention o incomplete artifact collection costituiscono failure inconclusivo. Il cleanup elimina command file e marker, revoca o rimuove la VM temporanea secondo policy e conserva soltanto gli artefatti approvati. `validation.md` contiene la procedura completa.

## 8. Analyst assessment and sources

La ricerca introduce una detection opportunity concreta: un programma di rete nativo che genera un Windows command shell per effetto di un documented local-command escape. La primitive è comportamentale e più durevole di hash, lure filename o dominio, ma non è ancora una production candidate. La decisione proporzionata è pubblicare un hunt Medium-confidence con score operativo 44/51 e score editoriale 25/28, mantenendo separati detection maturity, qualità narrativa e valore operativo.

La prossima verifica utile è il laboratorio positivo/negativo, non l'aggiunta di ulteriori filtri speculativi. Se la lineage è confermata, il passo seguente è misurare la prevalenza storica e classificare ogni automazione FTP legittima; soltanto allora si può valutare una alert rule. Se la lineage non è confermata, la query deve essere ridisegnata o ritirata.

Fonti aperte e verificate: FortiGuard Labs `S001`, Microsoft Defender XDR schema `S002`, Microsoft FTP command reference `S003`, MITRE ATT&CK `S004`. I claim sono nel ledger `evidence.json`; provenance e date sono in `references.json`; il piano operativo è in `validation.md`; la query completa è in `hunting.kql`. Il PDF canonico riassume autonomamente condizioni, meccanismo, sequenza, impatto, evidence boundary, detection e laboratorio.
