# NetworkMapper

NetworkMapper è un'applicazione progettata per mappare la topologia di rete. È composta da un backend in Python e un frontend moderno, costruito con Svelte e TailwindCSS.

## Caratteristiche principali
- Scansione della rete e mappatura dei dispositivi.
- Interfaccia utente intuitiva.
- Configurazione personalizzabile.

## Struttura del progetto
```plaintext
.
├── NetworkMapper.code-workspace
├── backend
│   ├── main.py
│   └── requirements.txt
├── docs
│   └── README.md
└── frontend
    ├── README.md  
    ├── package-lock.json
    ├── package.json
    ├── postcss.config.js
    ├── src
    │   ├── app.css
    │   ├── app.d.ts
    │   ├── app.html
    │   └── routes
    ├── static
    │   └── favicon.png
    ├── svelte.config.js
    ├── tailwind.config.ts
    ├── tsconfig.json
    └── vite.config.ts
```

## Requisiti
- Python 3.9+
- Node.js 16+

## Installazione
### Backend
1. Naviga nella directory `backend`:

    ```bash
    cd backend
    ```

2. Installa le dipendenze richieste:
    ```bash
   pip install -r requirements.txt
    ```
3. Avvia il backend:

    ```bash
    python ./main.py`
    ```
4. Lascia il terminale aperto.

### Frontend
1. Apri un nuovo terminale e naviga nella directory `frontend`:
    ```bash
    cd frontend`
    ```

2. Installa le dipendenze del frontend:
    ```bash
    npm install`
    ```

3. Avvia il server di sviluppo:
    ```bash
    npm run dev`
    ```

4. Apri il link mostrato nel terminale nel tuo browser per accedere all'interfaccia utente.
