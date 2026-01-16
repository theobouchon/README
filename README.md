# Veille automatisée des vulnérabilités CVE (CERT-FR)

Script **Python** qui :
1) collecte les bulletins **CERT-FR** (ANSSI) via leurs flux **RSS** (Avis + Alertes),  
2) extrait les identifiants **CVE**,  
3) enrichit les données via l’API **MITRE CVE (CVE AWG)** (description, produits, versions, CVSS, CWE…),  
4) récupère le score **EPSS** via l’API **FIRST.org**,  
5) déclenche une alerte email si une CVE est **CRITICAL**,  
6) exporte un fichier **CSV** (`projet.csv`).

---

## Sommaire
- [Fonctionnalités](#fonctionnalités)
- [Architecture du code](#architecture-du-code)
- [Données en sortie (CSV)](#données-en-sortie-csv)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Configuration de l’email](#configuration-de-lemail)
- [Exécution](#exécution)
- [Dépannage](#dépannage)
- [Limites et améliorations](#limites-et-améliorations)
- [Crédits et sources](#crédits-et-sources)

---

## Fonctionnalités

- Lecture des flux RSS CERT-FR :
  - Avis : `https://cert.ssi.gouv.fr/avis/feed/`
  - Alertes : `https://cert.ssi.gouv.fr/alerte/feed/`
- Extraction des identifiants CVE via expression régulière (`CVE-\d{4}-\d{4,7}`)
- Récupération des CVE par bulletin via endpoint JSON (URL bulletin + `json/`)
- Enrichissement pour chaque CVE via API MITRE (CVE AWG) :
  - description, vendor, produit, versions, CVSS (v4/v3/v2), sévérité, CWE
- Récupération du score EPSS via API FIRST.org
- Alerte email automatique si `Base Severity == CRITICAL`
- Export CSV : `projet.csv`

---

## Architecture du code

### 1) Imports & structures de données

- Imports :
  - `feedparser` : parse RSS
  - `requests` : appels HTTP (CERT-FR JSON, MITRE, EPSS)
  - `re` : regex pour extraire les CVE
  - `pandas` : création/export CSV
  - `smtplib` + `email.mime.text` : envoi email
- Structure centrale : `cve_dico` (dictionnaire “colonne → liste de valeurs”, converti en `DataFrame` à la fin)

### 2) Fonctions utilitaires

#### `extract_cvss(container)`
- Extrait **baseScore** et **baseSeverity** depuis les données MITRE
- Supporte plusieurs versions : `cvssV4_0`, `cvssV3_1`, `cvssV3_0`, `cvssV2`
- Retourne `(None, None)` si non disponible

#### `extract_cwe(container)`
- Extrait le champ `cweId` (ex. `CWE-79`)
- Supporte dict et liste, retourne `None` si absent

#### `send_email(to_email, subject, body)`
- Envoi d’email via SMTP Gmail (TLS, port 587)
- Étapes : création message MIME → connexion SMTP → `starttls()` → login → `sendmail()` → `quit()`

### 3) Collecte CERT-FR (RSS → bulletin JSON → CVE)
- Parse les flux RSS avis + alertes
- Pour chaque entrée : construit `entry.link + "json/"`, récupère `data["cves"]`
- Extrait les identifiants via regex
- Ajoute uniquement si pas déjà dans `cve_list`
- Remplit : type bulletin, lien, date, titre

### 4) Enrichissement MITRE (CVE AWG)
- Appelle `https://cveawg.mitre.org/api/cve/{cve_id}`
- Récupère : description, vendor, produit, versions affectées
- Extrait `Type CWE` (CNA d’abord, sinon ADP)
- Extrait `Score CVSS` + `Base Severity` (CNA d’abord, sinon ADP)

### 5) Alerte email (condition CRITICAL)
- Si `base_severity == "CRITICAL"` : envoie un email avec produit + description

### 6) Score EPSS (FIRST.org)
- Appelle `https://api.first.org/data/v1/epss?cve={cve_id}`
- Récupère `data[0]["epss"]` si présent

### 7) Export CSV
- Convertit `cve_dico` en `DataFrame`
- Exporte `projet.csv` sans index

---

## Données en sortie (CSV)

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

---

## Prérequis

- Python 3.8+ recommandé
- Accès Internet (CERT-FR, MITRE, FIRST)

---

## Installation

### 1) Installer les dépendances

```bash
pip install feedparser requests pandas
