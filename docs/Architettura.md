# Architettura del Progetto - NetworkMapper

L’architettura è suddivisa in più livelli e componenti principali:

                    ┌──────────────────┐
                    │    Front-End      │
                    │ (Svelte+Cytoscape)│
                    └───────┬──────────┘
                            │ REST API (JSON)
                            │
                  ┌─────────┴─────────┐
                  │      FASTAPI       │
                  │(Endpoints REST Pub.)│
                  └─────────┬─────────┘
                            │
                  ┌─────────┴──────────┐
                  │       CORE APP       │
                  │ (Service/Controller) │
                  └───┬─────────────────┘
                      │
              ┌───────┴───────────────────┐
              │         Plugin Manager      │
              │   (Caricamento, Registry)   │
              └───┬───────────────────┬────┘
                  │                   │
        ┌─────────┴───────┐   ┌─────┴─────────┐
        │   Scan Plugins   │   │   Storage/Out  │
        │ (Nmap, SNMP, ... )   │(In-Mem,DB,Export)
        └──────────────────┘   └───────────────┘

---

## **1. Core Application (Back-End)**

### **Main Controller / Service Layer**
- Il cuore dell’applicazione che gestisce:
  - La logica di scansione.
  - La memorizzazione temporanea dei dati (in memoria o su DB).
  - Le interfacce di servizio.

### **Plugin Manager**
- Modulo che:
  - Carica, registra e gestisce i plugin (es. scanner, parser, esportatori, fonti di dati).
  - Offre metodi standard per l’interazione con i plugin.
  - Garantisce che ogni plugin rispetti un’interfaccia comune.

### **Plugin Interface (API Interna)**
- Un set di interfacce:
  - Basate su Python (abstract classes o protocolli).
  - I plugin devono implementare queste interfacce per garantire interoperabilità.
  - Evita di legare il Core a un singolo tool.

---

## **2. Plugin di Scansione e Analisi**

### **Nmap Scan Plugin**
- Plugin che:
  - Implementa le chiamate a Nmap.
  - Gestisce parametri di scansione.
  - Estrae informazioni base (host, MAC, OS).
  - Esegue traceroute.

### **SNMP/SSH Info Plugin (Futuro)**
- Plugin separato che:
  - Arricchisce i dati dei nodi con informazioni provenienti da dispositivi autenticati.

### **OS/Service Fingerprinting Plugin**
- Plugin dedicato a:
  - Analizzare le informazioni di Nmap.
  - Estrarre OS e servizi in modo strutturato.

---

## **3. Plugin di Output e Storage**

### **In-Memory Storage Plugin**
- Plugin di default che:
  - Mantiene i dati (lista nodi, topologia) in memoria RAM.

### **DB Storage Plugin (Futuro)**
- Plugin che:
  - Salva i dati in un database (SQL/NoSQL).
  - Permette consultazioni storiche.

### **Export Plugin (JSON, CSV, PDF)**
- Plugin dedicati a:
  - Esportare i dati in formati standard.
  - Essere caricati o disabilitati a seconda delle esigenze.

---

## **4. REST API Layer (FastAPI)**

### **Endpoints Standard**
- Endpoints principali:
  - `/start_scan`, `/stop_scan`, `/nodes`.
  - Espongono le funzionalità del Core al front-end.

### **Gestione Sicurezza e Autenticazione**
- Componente opz
