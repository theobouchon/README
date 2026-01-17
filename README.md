# Veille automatisée des vulnérabilités CVE (CERT-FR)

Script **Python** qui :
1) Collecte les bulletins **CERT-FR** (ANSSI) via leurs flux **RSS** (Avis + Alertes)  
2) Extrait les identifiants **CVE** 
3) Enrichit les données via l’API CVE de MITRE (description, produits, versions, CVSS, CWE…)  
4) Récupère le score **EPSS** via l’API EPSS de FIRST  
5) Déclenche une alerte email si une CVE est **CRITICAL**  
6) Exporte un fichier **CSV** (`projet.csv`)

---

## Sommaire
- [Fonctionnalités](#fonctionnalités)
- [Architecture du code](#architecture-du-code)
- [Données en sortie (DataFrame et CSV)](#données-en-sortie-dataframe-et-csv)

---

## Fonctionnalités

- Lecture des flux RSS CERT-FR :
  - Avis : `https://cert.ssi.gouv.fr/avis/feed/`
  - Alertes : `https://cert.ssi.gouv.fr/alerte/feed/`
- Extraction des identifiants CVE via expression régulière (`CVE-\d{4}-\d{4,7}`)
- Récupération des CVE par bulletin via endpoint JSON (URL bulletin + `json/`)
  - extraction des flux RSS : Identifiant CVE, Titre du bulletin, Type de bulletin, Lien du bulletin, Date de publication
- Enrichissement pour chaque CVE via l'API de MITRE :
  - description, vendor, produit, versions, CVSS (v4/v3/v2), sévérité, CWE
- Récupération du score EPSS via API de FIRST
- Alerte email automatique si `Base Severity == CRITICAL`
- Export CSV : `projet.csv`

---

## Architecture du code

### 1) Imports & structures de données

- Imports :
  - `feedparser` : parse RSS
  - `requests` : appels HTTP (CERT-FR JSON, MITRE, EPSS)
  - `re` : regex pour extraire les CVE
  - `pandas` : création Dataframe et export CSV
  - `smtplib` + `email.mime.text` : envoi email
- Prérequis d'installation : `$ pip install feedparser`
- Structure centrale : `cve_dico` (dictionnaire “colonne → liste de valeurs”, converti en `DataFrame` à la fin)
    - Remplissage progressif de `cve_dico` lors du parcours des `cve_id` dans `cve_list` (valeurs → liste correspondante dans `cve_dico`) 

<img width="666" height="253" alt="Cve dico" src="https://github.com/user-attachments/assets/f50716a8-9f29-41a9-a1a4-0465aab10aae" />

### 2) Fonctions utilitaires

#### `extract_cvss(container)`
- Extrait **baseScore** et **baseSeverity** depuis les données MITRE
- Supporte plusieurs versions : `cvssV4_0`, `cvssV3_1`, `cvssV3_0`, `cvssV2`
- Retourne `(None, None)` si non disponible

<img width="639" height="287" alt="extract_cvss" src="https://github.com/user-attachments/assets/1cca2af8-9520-4da9-9449-1e032de2ff5c" />

#### `extract_cwe(container)`
- Extrait le champ `cweId` (ex. `CWE-79`)
- Supporte dict `container = 'cna'` et liste `container = 'adp'`, retourne `None` si absent

<img width="956" height="177" alt="extract_cwe" src="https://github.com/user-attachments/assets/70c22111-b54c-4cc2-9a59-5777b068a2e0" />

#### `send_email(to_email, subject, body)`
- Envoi d’email via SMTP Gmail (TLS, port 587)
- Étapes : création message MIME → connexion SMTP → `starttls()` → login → `sendmail()` → `quit()`
  
<img width="530" height="288" alt="Mail code" src="https://github.com/user-attachments/assets/c4e577ee-b6f3-4cda-b343-edb0a2db44ed" />

### 3) Collecte CERT-FR (RSS → bulletin JSON → CVE)
- Parse les flux RSS avis + alertes
- Pour chaque entrée : construit `entry.link + "json/"`, récupère `data["cves"]`
- Extrait les identifiants via regex
- Ajoute uniquement si pas déjà dans `cve_list`
- Remplit : type bulletin, lien, date, titre
  
<img width="752" height="702" alt="Code partie 1" src="https://github.com/user-attachments/assets/e9974942-c2a6-4a35-bc0a-372cae3bcd11" />

### 4) Enrichissement MITRE (CVE AWG)
- Appelle `https://cveawg.mitre.org/api/cve/{cve_id}`
- Récupère pour chaque `cve_id` dans `cve_list` : description, vendor, produit, versions affectées
- Utilisation de `set_vendor` et `set_product` pour supprimer les répétitions de `vendor` et `product`
  
<img width="759" height="694" alt="Code partie 2" src="https://github.com/user-attachments/assets/ef803a62-1d55-496b-ad9a-2060d7521b95" />

- Extrait Type CWE (CNA d’abord, sinon ADP)
- Extrait Score CVSS + Base Severity (CNA d’abord, sinon ADP)
- Impératif de valider l'existence dans `cna` et `adp` sous peine de manquer des informations pourtant bien présentes
  - Cause : Suivant le `cve_id`, le `metrics` conteant `cweId`, `baseScore` et `baseSeverity` est soit présent dans `cna` soit présent dans `adp` ; `cna` et `adp` sont parfois tout les deux présents dans le même `cve_id.data`
  
<img width="1072" height="247" alt="Code partie 3" src="https://github.com/user-attachments/assets/7f051438-1f8c-4fa2-b89b-b4f2f09b10b4" />

### 5) Alerte email (condition CRITICAL)
- Si `base_severity == "CRITICAL"` : envoie un email avec produit + description

<img width="1304" height="62" alt="Envoie mail" src="https://github.com/user-attachments/assets/4cb4e285-6743-4e21-9077-a578a6fd4360" />
<img width="915" height="209" alt="Base severity" src="https://github.com/user-attachments/assets/ae69c070-0941-4873-906b-f1be3de31b25" />
<img width="890" height="184" alt="Mail envoyé" src="https://github.com/user-attachments/assets/0d660e1f-3ad8-4d39-a14b-61b92a225f91" />
<img width="1386" height="200" alt="Mail reçu" src="https://github.com/user-attachments/assets/072b67bb-aa7a-4458-9ac8-dd62de56754a" />
<img width="1512" height="310" alt="Mail2" src="https://github.com/user-attachments/assets/1dce1135-191b-4221-ae86-e396adab4f04" />

### 6) Score EPSS (FIRST.org)
- Appelle `https://api.first.org/data/v1/epss?cve={cve_id}`
- Récupère `data[0]["epss"]` si présent

<img width="705" height="117" alt="Score EPSS" src="https://github.com/user-attachments/assets/ef3feaef-20c3-4e26-bef2-4c5a1ff6159a" />

### 7) Export CSV
- Convertit `cve_dico` en `DataFrame` : l'architecture utilisée pour `cve_dico` facilite la conversion
- Exporte `projet.csv` sans index
<img width="439" height="49" alt="Création du dataframe" src="https://github.com/user-attachments/assets/9541cc88-c226-4309-b125-85e3f526db0e" />

---

## Données en sortie (DataFrame et CSV)

Colonnes exportées :
- `Identifiant CVE`
- `Description`
- `Score CVSS`
- `Type CWE`
- `Score EPSS`
- `Base Severity`
- `Titre du bulletin`
- `Date de publication`
- `Lien du bulletin`
- `Vendor`
- `Produit`
- `Versions affectées`
- `Type de bulletin`
  
<img width="1893" height="886" alt="Dataframe" src="https://github.com/user-attachments/assets/801d4ea8-fdaa-4a3a-9d60-0e69d5585aab" />

---

## Merci de votre attention 
