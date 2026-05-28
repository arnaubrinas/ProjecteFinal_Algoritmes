#  Clasificador de Correos Spam/Phishing

> Sistema de detecció i classificació automàtica de correus electrònics maliciosos mitjançant estructures de dades avançades i tècniques de ciberseguretat.

---

##  Descripció breu

Sistema que analitza arxius `.eml` per detectar spam i phishing. Utilitza un Arbre Binari de Cerca (BST) per indexar paraules sospechoses, distància de Levenshtein per detectar typosquatting, i un escàner recursiu de carpetes per processar múltiples correus. Els correus marcats com a perillosos o sospitosos es mouen automàticament a una carpeta de quarantena.

---

##  Integrants del grup

- **Pol Sánchez**
- **Arnau Briñas**

---

##  Context i problemàtica

El phishing i el spam són dues de les amenaces més esteses en ciberseguretat. Segons l'APWG, milions de correus maliciosos es distribueixen diàriament, molts d'ells imitant entitats legítimes (bancs, serveis de correu, organismes públics) per robar credencials o infectar dispositius.

El repte principal és la detecció eficient: un sistema real ha d'analitzar milers de correus ràpidament i amb el mínim de falsos positius. Aquest projecte aborda aquest problema amb:

- **Estructures de dades eficients** (BST per a cerques en O(log n))
- **Algorismes de similitud** (Levenshtein per detectar dominis falsificats)
- **Automatització** (escàner recursiu + quarantena automàtica)

---

##  Funcionalitats principals

| # | Funcionalitat | Descripció |
|---|--------------|------------|
| 1 | **Classificació per paraules clau** | BST amb +50 paraules sospitoses amb pes de risc. Detecta urgència, premis, credencials, etc. |
| 2 | **Detecció de typosquatting** | Distància de Levenshtein per identificar dominis que imiten legítims (ex: `santanderr.com` → `santander.com`) |
| 3 | **Llista negra de dominis** | Comprovació directa contra dominis coneguts com a malignes (URL shorteners, correus temporals...) |
| 4 | **Escàner recursiu de carpetes** | Recorre qualsevol profunditat de subcarpetes buscant arxius `.eml` |
| 5 | **Sistema de quarantena automàtica** | Mou els correus SOSPITOSOS i PERILLOSOS a una carpeta separada |
| 6 | **Puntuació de risc dinàmica** | Acumula puntuació per cada indicador trobat. Tres nivells: SEGUR / SOSPITÓS / PERILLÓS |
| 7 | **Reporte detallat per consola** | Mostra resum total i detall per cada correu analitzat |
| 8 | **Mode demo** | Genera correus `.eml` de prova automàticament per a demostracions |

---

##  Ús de POO i polimorfisme

### Classes principals

```
FiltroCorreo (classe base abstracta)
├── FiltroPorPalabrasClave
└── FiltroPorRemitenteSospechoso

NodoBST
ArbolBST
AnalizadorCorreo
```

### Descripció de cada classe

| Classe | Responsabilitat |
|--------|----------------|
| `NodoBST` | Node de l'arbre BST. Emmagatzema paraula, pes de risc i freqüència |
| `ArbolBST` | Arbre Binari de Cerca complet. Inserció, cerca i recorregut in-order recursiu |
| `FiltroCorreo` | **Classe base abstracta**. Defineix la interfície `analizar()` que han d'implementar tots els filtres |
| `FiltroPorPalabrasClave` | Hereta de `FiltroCorreo`. Analitza asumpte i cos del correu buscant paraules sospitoses al BST |
| `FiltroPorRemitenteSospechoso` | Hereta de `FiltroCorreo`. Avalua el domini del remitent i les URLs del cos |
| `AnalizadorCorreo` | Orquestra tots els filtres. Llegeix arxius `.eml` i combina els resultats |

### On apareix el polimorfisme

El polimorfisme és el nucli del sistema de filtres. `AnalizadorCorreo` manté una llista de tipus `list[FiltroCorreo]`:

```python
self.filtros: list[FiltroCorreo] = [
    FiltroPorPalabrasClave(),
    FiltroPorRemitenteSospechoso(),
]
```

En el moment d'analitzar, itera per tots els filtres cridant `.analizar()` de forma **polimòrfica**: cada filtre executa la seva pròpia implementació sense que `AnalizadorCorreo` necessiti saber de quin tipus concret es tracta. Afegir un nou filtre és tan simple com crear una nova subclasse i afegir-la a la llista.

```python
for filtro in self.filtros:
    pts, razones = filtro.analizar(asunto, cuerpo, remitente)  # ← polimorfisme
```

---

##  Instruccions d'execució i dependències

### Requisits

- Python **3.10+**
- Sense dependències externes  únicament llibreries estàndard de Python (`os`, `re`, `email`, `shutil`)

### Execució

**Mode demo** (genera correus de prova automàticament):
```bash
python clasificador.py
```

**Mode real** (analitza una carpeta de correus `.eml`):
```bash
python clasificador.py <carpeta_correus> [carpeta_quarantena]
```

**Exemples:**
```bash
python clasificador.py ./correus_entrada
python clasificador.py ./correus_entrada ./quarantena_sortida
```

### Estructura de carpetes esperada

```
/
PROJECTEFINAL_ALGORITMES/
├── docs/
│   ├── conclusions_i_propostes_futur.pdf
│   ├── estudi_complexitat.pdf
│   ├── flux_funcionalitat_1.png
│   ├── flux_funcionalitat_2.png
│   └── uml.png
├── source/
│   └── clasificador.py
├── .gitignore
└── README.md
```

---

##  Vídeo demostratiu

>  LINK


---

##  Ús d’intel·ligència artificial
S’ha utilitzat de manera puntual intel·ligència artificial a algunes parts del codi del projecte, però s'ha indicat específicament a les linies de codi que s'ha fet servir. També l'hem fet servir com a suport per aclarir dubtes generals sobre l’estructura del projecte. Tot i així el codi l'hem entès, adaptat i implementat manualment.

##  Resum de complexitat algorítmica

| Operació | Complexitat |
|----------|------------|
| Inserció al BST | O(log n) mitjana · O(n) pitjor cas |
| Cerca al BST | O(log n) mitjana · O(n) pitjor cas |
| Recorregut in-order (càlcul risc) | O(n) |
| Distància de Levenshtein | O(m × n) |
| Escàner recursiu de carpetes | O(f) on f = nombre d'arxius .eml |
| Anàlisi d'un correu (tots els filtres) | O(p · log p + d · L) on p = paraules BST, d = dominis extrets, L = longitud dominis |

---

