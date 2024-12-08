# -*- coding: utf-8 -*-
"""
Script Extracteur SIRET/SIREN par Vigilantia

Ce script permet d'extraire les numéros SIRET et SIREN à partir des sites web fournis
dans un fichier CSV d'entrée. Il utilise une approche basée sur le crawling des sitemaps
et l'exploration de liens internes pertinents (mentions légales, politique de confidentialité,
etc.) pour localiser les pages susceptibles de contenir ces informations.

Étapes principales :
1. Détermination de l'URL de base du site (test de schémas communs : https, http, www).
2. Récupération du sitemap à partir de robots.txt ou utilisation de sitemap.xml par défaut.
3. Analyse récursive du sitemap pour extraire des URLs de pages légales.
4. Si aucune page légale n'est trouvée via le sitemap, exploration des liens internes de la homepage.
5. Extraction des SIRET/SIREN via des motifs regex et filtrage des identifiants ignorés.
6. Écriture des résultats dans un fichier CSV de sortie.

Configuration :
- Possibilité de définir la variable d'environnement "IGNORED_NUMBERS" pour ignorer certains numéros.
- Fonctionne avec Python 3.9+.

Auteur : Vigilantia
"""

import os
import re
import requests
from urllib.parse import urlparse, urljoin
from lxml import etree, html
import csv
import sys
import unicodedata
import logging

# ===========================================================
# CONFIGURATION & CONSTANTES
# ===========================================================

# Logger configuration
logging.basicConfig(
    level=logging.INFO, 
    format='[%(asctime)s] %(levelname)s :: %(message)s', 
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("SIRETExtractor")

TIMEOUT = 5
HEADERS = {'User-Agent': 'Mozilla/5.0'}
IGNORED_NUMBERS = os.environ.get("IGNORED_NUMBERS", "")  # Liste de SIREN/SIRET à ignorer, séparés par virgule

SIREN_PATTERN = r'\b(\d{3}\s?\d{3}\s?\d{3})\b'
SIRET_PATTERN = r'\b(\d{3}\s?\d{3}\s?\d{3}\s?\d{5})\b'

CANDIDATE_KEYWORDS = [
    "mentions", "mentions-legales", "mentions-légales", "legal", "legales", "légales",
    "cgu", "cgv", "infos", "contact", "a-propos", "about", "about-us", "impressum",
    "privacy", "policy", "terms", "conditions", "terms-and-conditions", "informations-legales",
    "informations-légales", "legal-notice", "legalnotice", "terms-of-service", "terms-of-use",
    "conditions-generales-de-vente", "politique-de-confidentialite", "politique-confidentialite",
    "rgpd", "gdpr", "data-protection", "protection-des-donnees", "private-policy", "termes",
    "charte", "conditions-generales", "conditionsgenerales", "informations", "mentions-obligatoires",
    "mentionsobligatoires", "avis-juridiques", "disclaimer", "cookies", "cookie-policy",
    "avis-legaux", "legal-information", "legalinformation"
]


# ===========================================================
# FONCTIONS UTILITAIRES
# ===========================================================

def normalize_text(text):
    """Normalise le texte : supprime les accents et convertit en minuscules."""
    return ''.join(c for c in unicodedata.normalize('NFD', text) if not unicodedata.combining(c)).lower()


def filter_candidate_urls(urls):
    candidates = []
    normalized_keywords = [normalize_text(keyword) for keyword in CANDIDATE_KEYWORDS]
    for u in urls:
        normalized_url = normalize_text(u)
        if any(keyword in normalized_url for keyword in normalized_keywords):
            candidates.append(u)
    return candidates


def fetch_url(url, timeout=TIMEOUT):
    """Effectue une requête GET sur l'URL, avec gestion des exceptions et timeout."""
    try:
        resp = requests.get(url, headers=HEADERS, timeout=timeout)
        return resp
    except requests.RequestException as e:
        logger.warning(f"Failed to fetch URL: {url} | Reason: {e}")
        return None


def guess_base_url(domain):
    """
    Devine l'URL de base pour un domaine donné.
    Teste https, http, avec ou sans www.
    Tente une correction des erreurs typographiques.
    """
    schemes = [
        f"https://{domain}",
        f"http://{domain}",
        f"https://www.{domain}",
        f"http://www.{domain}"
    ]

    for url in schemes:
        resp = fetch_url(url)
        if resp and resp.status_code in range(200, 400):
            logger.debug(f"Base URL determined for {domain}: {resp.url}")
            return resp.url

    # Tentative de correction d'erreur typographique
    if domain.startswith("www") and '.' not in domain[3:]:
        corrected = "www." + domain[3:]
        return guess_base_url(corrected)

    logger.debug(f"No base URL found for {domain}.")
    return None


def extract_sitemap_url(base_url):
    """
    Récupère l'URL du sitemap depuis le fichier robots.txt.
    Si aucune info n'est trouvée, utilise base_url/sitemap.xml par défaut.
    """
    if not base_url:
        return None
    parsed = urlparse(base_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    resp = fetch_url(robots_url)
    sitemap_url = None
    if resp and resp.status_code == 200:
        for line in resp.text.splitlines():
            if line.lower().startswith("sitemap:"):
                sitemap_url = line.split(":", 1)[1].strip()
                logger.debug(f"Sitemap found in robots.txt: {sitemap_url}")
                break
    if not sitemap_url:
        sitemap_url = urljoin(base_url, "sitemap.xml")
        logger.debug(f"No sitemap in robots.txt, fallback to: {sitemap_url}")
    return sitemap_url


def parse_sitemap(url, visited=None):
    if visited is None:
        visited = set()

    if not url or url in visited:
        return []
    visited.add(url)

    resp = fetch_url(url)
    if not (resp and resp.status_code == 200):
        return []

    try:
        root = etree.fromstring(resp.content)
    except etree.XMLSyntaxError:
        return []

    ns = {'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
    urls = []

    # Index de sitemap
    sitemap_tags = root.findall('.//sm:sitemap/sm:loc', ns)
    if sitemap_tags:
        for loc in sitemap_tags:
            sub_sitemap_url = loc.text.strip()
            urls.extend(parse_sitemap(sub_sitemap_url, visited=visited))

    # URL set standard
    url_tags = root.findall('.//sm:url/sm:loc', ns)
    for loc in url_tags:
        urls.append(loc.text.strip())

    return urls


def extract_siren_siret_from_text(text):
    found_numbers = set()
    ignored = [num.strip() for num in IGNORED_NUMBERS.split(',') if num.strip()]

    # Extraction SIRET
    siret_matches = re.findall(SIRET_PATTERN, text)
    for s in siret_matches:
        clean_s = re.sub(r'\s+', '', s)
        if clean_s not in ignored:
            found_numbers.add(clean_s)

    if found_numbers:
        return list(found_numbers)

    # Extraction SIREN si pas de SIRET
    siren_matches = re.findall(SIREN_PATTERN, text)
    for s in siren_matches:
        clean_s = re.sub(r'\s+', '', s)
        if clean_s not in ignored:
            found_numbers.add(clean_s)

    return list(found_numbers)


def extract_siren_siret_from_page(url):
    if not url:
        return []
    resp = fetch_url(url)
    if not (resp and resp.status_code == 200):
        return []

    doc = html.fromstring(resp.content)
    # Remove unwanted tags
    for bad_tag in doc.xpath('//script | //style | //meta'):
        parent = bad_tag.getparent()
        if parent is not None:
            parent.remove(bad_tag)

    text_content = doc.xpath('//body//text()')
    text = " ".join(t.strip() for t in text_content if t.strip())

    return extract_siren_siret_from_text(text)


def crawl_internal_links(base_url):
    candidates = []
    if not base_url:
        return candidates

    resp = fetch_url(base_url)
    if not (resp and resp.status_code == 200):
        return candidates

    doc = html.fromstring(resp.content)
    links = doc.xpath('//a[@href]')
    visited = set()

    def is_internal_link(link):
        parsed_base = urlparse(base_url)
        parsed_link = urlparse(link)
        return parsed_link.netloc == "" or parsed_link.netloc == parsed_base.netloc

    for link in links:
        href = link.get('href')
        if href:
            full_url = urljoin(base_url, href)
            if is_internal_link(full_url) and full_url not in visited:
                visited.add(full_url)
                if any(keyword in full_url.lower() for keyword in CANDIDATE_KEYWORDS):
                    candidates.append(full_url)

    return candidates


def find_siret_siren(domain):
    if not domain:
        return []

    logger.info(f"Processing domain: {domain}")
    base_url = guess_base_url(domain)
    if not base_url:
        logger.warning(f"No accessible base URL found for domain: {domain}")
        return []

    sitemap_url = extract_sitemap_url(base_url)
    sitemap_urls = parse_sitemap(sitemap_url)
    candidates = filter_candidate_urls(sitemap_urls)

    if not candidates:
        logger.debug("No candidates found via sitemap, attempting internal crawl.")
        internal_candidates = crawl_internal_links(base_url)
        candidates.extend(internal_candidates)

    for c in candidates:
        found = extract_siren_siret_from_page(c)
        if found:
            logger.info(f"Found SIRET/SIREN for {domain} on {c}: {found}")
            return found

    # Fallback
    found = extract_siren_siret_from_page(base_url)
    if found:
        logger.info(f"Found SIRET/SIREN for {domain} on homepage: {found}")
    else:
        logger.info(f"No SIRET/SIREN found for {domain}")
    return found


# ===========================================================
# MAIN
# ===========================================================

def print_cyberpunk_banner():
    # Simple ASCII banner with some ANSI colors and a cyberpunk feel
    # Using ANSI escape sequences for colors: \x1b[...m
    cyan = "\x1b[36m"
    magenta = "\x1b[35m"
    reset = "\x1b[0m"
    banner = f"""
{magenta}┌──────────────────────────────────────────┐{reset}
{magenta}│{reset}   {cyan}S I R E T   &   S I R E N   E X T R A C T O R{reset}   {magenta}│{reset}
{magenta}└──────────────────────────────────────────┘{reset}
  {cyan}(by Vigilantia){reset}

"""
    print(banner)


if __name__ == "__main__":
    print_cyberpunk_banner()

    if len(sys.argv) < 3:
        print("Usage: python siret_extractor.py input.csv output.csv")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    logger.info(f"Input CSV: {input_file}, Output CSV: {output_file}")

    if not os.path.exists(input_file):
        logger.error(f"Input file does not exist: {input_file}")
        sys.exit(1)

    results = []
    with open(input_file, newline='', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        if 'domain' not in reader.fieldnames:
            logger.error("Input file must contain a 'domain' column.")
            sys.exit(1)

        for row in reader:
            domain = row['domain'].strip()
            if not domain:
                logger.warning("Empty domain encountered, skipping.")
                results.append({'domain': domain, 'result': "None"})
                continue

            found = find_siret_siren(domain)
            result_str = ",".join(found) if found else "None"
            results.append({'domain': domain, 'result': result_str})

    with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=['domain', 'result'])
        writer.writeheader()
        for r in results:
            writer.writerow(r)

    logger.info(f"Results written to {output_file}")
    print("\n\x1b[32mExtraction Completed Successfully!\x1b[0m\n")
