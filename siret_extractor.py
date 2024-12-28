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
import urllib3
import warnings
from urllib.parse import urlparse, urljoin
from lxml import etree, html
import csv
import sys
import unicodedata
import logging
import time
from datetime import datetime
from functools import lru_cache
from typing import List, Tuple
from browser_utils import fetch_url_with_browser
from bs4 import BeautifulSoup

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

# Configuration des timeouts et tentatives
TIMEOUT = 10  # Timeout plus long pour sites lents
CONNECT_TIMEOUT = 5  # Timeout spécifique pour la connexion
MAX_RETRIES = 2  # Moins de retries mais plus intelligents
BACKOFF_FACTOR = 1  # Attente plus longue entre les tentatives

# Headers modernes et réalistes
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
    'Accept-Encoding': 'gzip, deflate',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
    'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-User': '?1',
    'Sec-Fetch-Dest': 'document',
    'Connection': 'keep-alive'
}

IGNORED_NUMBERS = os.environ.get("IGNORED_NUMBERS", "")  # Liste de SIREN/SIRET à ignorer, séparés par virgule

# Patterns for SIREN, SIRET and Email
EMAIL_PATTERN = r'[\w\.-]+@[\w\.-]+\.\w+'

CANDIDATE_KEYWORDS = [
    # French variations
    "mentions", "mentions-legales", "mentions-légales", "legal", "legales", "légales",
    "mentions_legales", "mentions_légales", "mentionslegales", "mentionslégales",
    # Common paths
    "fr/terms", "fr/legal", "fr/mentions-legales", "fr/mentions", "fr/cgu",
    "en/terms", "en/legal", "en/legal-notice",
    # Standard terms
    "cgu", "cgv", "infos", "contact", "a-propos", "about", "about-us", "impressum",
    "privacy", "policy", "terms", "conditions", "terms-and-conditions",
    "informations-legales", "informations-légales", "legal-notice", "legalnotice",
    "terms-of-service", "terms-of-use", "conditions-generales-de-vente",
    "politique-de-confidentialite", "politique-confidentialite",
    # Additional variations
    "rgpd", "gdpr", "data-protection", "protection-des-donnees", "private-policy",
    "termes", "charte", "conditions-generales", "conditionsgenerales",
    "informations", "mentions-obligatoires", "mentionsobligatoires",
    "avis-juridiques", "disclaimer", "cookies", "cookie-policy",
    "avis-legaux", "legal-information", "legalinformation",
    # Common footer paths
    "footer/legal", "footer/terms", "footer/mentions-legales",
    # No extension variations
    "legal.html", "legal.php", "mentions-legales.html", "mentions-legales.php",
    "terms.html", "terms.php"
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


# Cache pour les requêtes HTTP avec une taille maximale de 1000 entrées
@lru_cache(maxsize=1000)
def cached_fetch(url):
    """Version mise en cache de fetch_url"""
    return fetch_url(url)


def fetch_url(url, timeout=(CONNECT_TIMEOUT, TIMEOUT)):
    """Effectue une requête GET sur l'URL avec une configuration optimisée."""
    session = requests.Session()
    
    # Configuration de base de la session
    session.verify = False
    session.headers.update(HEADERS)
    session.trust_env = False  # Ignore les variables d'environnement proxy
    
    # Adapter personnalisé avec configuration optimisée
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=100,
        pool_maxsize=100,
        max_retries=MAX_RETRIES,
        pool_block=False
    )
    
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    try:
        # Suppression silencieuse des avertissements SSL
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
            
            # Première tentative avec HTTPS
            try:
                response = session.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    stream=True  # Évite de charger tout le contenu immédiatement
                )
                response.raise_for_status()
                return response
                
            except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
                # Si HTTPS échoue, on essaie HTTP
                if url.startswith('https://'):
                    url_http = url.replace('https://', 'http://')
                    response = session.get(
                        url_http,
                        timeout=timeout,
                        allow_redirects=True,
                        stream=True
                    )
                    response.raise_for_status()
                    return response
                raise
                
    except requests.exceptions.RequestException as e:
        logger.debug(f"Failed to fetch URL: {url} | {str(e)}")
        return None
        
    finally:
        session.close()


def guess_base_url(domain):
    """Devine l'URL de base pour un domaine avec gestion intelligente des variantes."""
    if not domain:
        return None
        
    # Nettoyage du domaine
    domain = domain.lower().strip()
    if domain.startswith(('http://', 'https://')):
        parsed = urlparse(domain)
        domain = parsed.netloc
        
    # Liste des variantes à tester
    variants = [
        f"https://www.{domain}",  # Priorité au HTTPS avec www
        f"https://{domain}",      # Puis HTTPS sans www
        f"http://www.{domain}",   # Puis HTTP avec www
        f"http://{domain}"        # Enfin HTTP sans www
    ]
    
    # Test de chaque variante
    for url in variants:
        response = fetch_url(url)
        if response and response.status_code == 200:
            final_url = response.url
            logger.debug(f"Successfully connected to {final_url}")
            return final_url
            
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
    resp = cached_fetch(robots_url)
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

    resp = cached_fetch(url)
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


def decode_obfuscated_email(text: str) -> str:
    """
    Décode les emails obfusqués dans le texte.
    Ex: 'contact [at] domain [dot] fr' -> 'contact@domain.fr'
    """
    # Liste des remplacements courants
    replacements = {
        r'\[at\]': '@',
        r'\(at\)': '@',
        r' at ': '@',
        r'\[dot\]': '.',
        r'\(dot\)': '.',
        r' dot ': '.',
        r'\[point\]': '.',
        r'\(point\)': '.',
        r' point ': '.',
    }
    
    # Applique les remplacements
    cleaned = text.lower()
    for pattern, repl in replacements.items():
        cleaned = re.sub(pattern, repl, cleaned, flags=re.IGNORECASE)
    
    return cleaned

def has_context_keywords(text: str, position: int, window_size: int = 10) -> bool:
    """
    Vérifie si des mots-clés pertinents sont présents autour de la position donnée.
    """
    keywords = {
        'siret', 'siren', 'rcs', 'numero', 'numéro', 'n°', 'immatriculation',
        'registre', 'commerce', 'sociétés', 'societes', 'entreprise',
        'identification', 'tva', 'fiscal', 'fiscale'
    }
    
    # Extrait le contexte avant et après
    words = text.lower().split()
    if not words:
        return False
        
    # Trouve l'index du mot le plus proche de la position
    char_count = 0
    word_index = 0
    for i, word in enumerate(words):
        char_count += len(word) + 1  # +1 pour l'espace
        if char_count >= position:
            word_index = i
            break
    
    # Extrait la fenêtre de mots
    start = max(0, word_index - window_size)
    end = min(len(words), word_index + window_size)
    context_window = words[start:end]
    
    # Vérifie si un mot-clé est présent
    return any(keyword in context_window for keyword in keywords)

def normalize_number(text: str) -> str:
    """
    Normalise un numéro en enlevant les espaces et la ponctuation.
    """
    return re.sub(r'[^0-9]', '', text)

def extract_siren_siret(text: str) -> Tuple[List[str], List[str]]:
    """
    Extrait les numéros SIREN (9 chiffres) et SIRET (14 chiffres) du texte
    avec vérification du contexte.
    """
    # Patterns plus flexibles
    siren_pattern = r'(?:^|[^\d])(\d{3}[ .-]?\d{3}[ .-]?\d{3})(?:[^\d]|$)'
    siret_pattern = r'(?:^|[^\d])(\d{3}[ .-]?\d{3}[ .-]?\d{3}[ .-]?\d{5})(?:[^\d]|$)'
    
    sirens = []
    sirets = []
    
    # Recherche des SIRET (14 chiffres)
    for match in re.finditer(siret_pattern, text, re.MULTILINE):
        num = match.group(1)
        pos = match.start(1)
        if has_context_keywords(text, pos):
            normalized = normalize_number(num)
            if len(normalized) == 14:
                sirets.append(normalized)
    
    # Recherche des SIREN (9 chiffres)
    for match in re.finditer(siren_pattern, text, re.MULTILINE):
        num = match.group(1)
        pos = match.start(1)
        if has_context_keywords(text, pos):
            normalized = normalize_number(num)
            if len(normalized) == 9 and normalized not in [s[:9] for s in sirets]:
                sirens.append(normalized)
    
    return list(set(sirens)), list(set(sirets))

def extract_emails(text: str) -> List[str]:
    """
    Extrait les adresses email du texte, y compris les formats obfusqués.
    """
    # Décode d'abord les emails obfusqués
    decoded_text = decode_obfuscated_email(text)
    
    # Pattern email plus complet
    email_pattern = r'''(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])'''
    
    emails = []
    for match in re.finditer(email_pattern, decoded_text, re.IGNORECASE):
        email = match.group(0).lower()
        if email not in emails:
            emails.append(email)
    
    return emails


def score_url(url: str, text: str = "") -> float:
    """
    Score une URL basé sur sa probabilité de contenir des informations légales.
    """
    score = 0.0
    
    # Mots clés dans l'URL
    url_keywords = {
        'mention': 2.0,
        'legal': 2.0,
        'contact': 1.5,
        'about': 1.0,
        'apropos': 1.0,
        'entreprise': 1.0,
        'societe': 1.0,
        'cgv': 1.5,
        'condition': 1.0,
        'rcs': 2.0,
        'siret': 2.0,
        'siren': 2.0,
    }
    
    # Mots clés dans le texte
    text_keywords = {
        'siren': 2.0,
        'siret': 2.0,
        'rcs': 1.5,
        'société': 1.0,
        'capital': 1.0,
        'immatriculation': 1.5,
        'registre': 1.0,
        'commerce': 1.0,
    }
    
    # Score basé sur l'URL
    url_lower = url.lower()
    for keyword, weight in url_keywords.items():
        if keyword in url_lower:
            score += weight
    
    # Score basé sur le texte
    if text:
        text_lower = text.lower()
        for keyword, weight in text_keywords.items():
            if keyword in text_lower:
                score += weight
    
    return score


def crawl_page(base_url: str, max_pages: int = 10) -> List[str]:
    """
    Crawl simple d'un site web pour trouver des pages pertinentes.
    """
    visited = set()
    to_visit = {base_url}
    found_urls = []
    
    while to_visit and len(found_urls) < max_pages:
        try:
            url = to_visit.pop()
            if url in visited:
                continue
                
            visited.add(url)
            
            # Récupère la page
            response = requests.get(
                url,
                headers=HEADERS,
                verify=False,
                timeout=(CONNECT_TIMEOUT, TIMEOUT)
            )
            response.raise_for_status()
            
            # Parse le HTML
            tree = html.fromstring(response.content)
            
            # Score la page
            page_score = score_url(url, response.text)
            if page_score > 1.0:
                found_urls.append(url)
            
            # Trouve les liens
            for href in tree.xpath('//a/@href'):
                try:
                    # Normalise l'URL
                    full_url = urljoin(base_url, href)
                    
                    # Vérifie si l'URL est sur le même domaine
                    if urlparse(full_url).netloc == urlparse(base_url).netloc:
                        to_visit.add(full_url)
                except:
                    continue
                    
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")
            continue
            
    return found_urls


def crawl_site(base_url: str, max_depth: int = 2, max_pages: int = 20) -> List[str]:
    """
    Crawl plus agressif d'un site web.
    """
    logger.info(f"Starting enhanced crawl of {base_url}")
    visited = set()
    found_urls = set()
    queue = [(base_url, 0)]  # (url, depth)
    
    while queue and len(visited) < max_pages:
        current_url, depth = queue.pop(0)
        if current_url in visited or depth > max_depth:
            continue
            
        visited.add(current_url)
        logger.debug(f"Crawling {current_url} at depth {depth}")
        
        try:
            # Try regular request first
            response = fetch_url(current_url)
            if not response or not response.ok:
                # If regular request fails, try with browser
                logger.info(f"Regular request failed for {current_url}, trying with browser")
                content = fetch_url_with_browser(current_url)
                if not content:
                    continue
            else:
                content = response.text
                
            # Parse the content
            soup = BeautifulSoup(content, 'html.parser')
            
            # First check footer links (higher priority)
            footer_tags = soup.find_all(['footer', 'div'], class_=lambda x: x and any(word in x.lower() for word in ['footer', 'bottom', 'bas-page']))
            for footer in footer_tags:
                for link in footer.find_all('a', href=True):
                    url = urljoin(base_url, link.get('href'))
                    if url.startswith(('http://', 'https://')):
                        found_urls.add(url)
                        if depth < max_depth and url not in visited:
                            queue.append((url, depth + 1))
            
            # Then check regular links
            for link in soup.find_all('a', href=True):
                url = urljoin(base_url, link.get('href'))
                if url.startswith(('http://', 'https://')):
                    # Score the URL based on both the URL itself and the link text
                    link_text = link.get_text().lower()
                    if any(keyword in link_text for keyword in CANDIDATE_KEYWORDS):
                        found_urls.add(url)
                        if depth < max_depth and url not in visited:
                            queue.append((url, depth + 1))
                            
            # Extract frames and iframes (sometimes legal notices are embedded)
            for frame in soup.find_all(['frame', 'iframe']):
                src = frame.get('src', '')
                if src:
                    url = urljoin(base_url, src)
                    if url.startswith(('http://', 'https://')):
                        found_urls.add(url)
                        
        except Exception as e:
            logger.error(f"Error crawling {current_url}: {str(e)}")
            continue
            
    return list(found_urls)

def process_domain(domain: str) -> Tuple[List[str], List[str], List[str]]:
    """
    Traite un domaine en cherchant les SIREN, SIRET et emails.
    """
    logger.info(f"Processing domain: {domain}")
    base_url = guess_base_url(domain)
    
    if not base_url:
        logger.error(f"No working base URL found for domain: {domain}")
        return set(), set(), set()
        
    all_siren = set()
    all_siret = set()
    all_emails = set()
    processed_urls = set()
    
    try:
        # First try to get URLs from sitemap
        sitemap_url = extract_sitemap_url(base_url)
        if sitemap_url:
            urls = get_urls_from_sitemap(sitemap_url)
            logger.info(f"Found {len(urls)} URLs in sitemap")
            
            # Filter and score URLs
            scored_urls = [(url, score_url(url)) for url in urls]
            scored_urls.sort(key=lambda x: x[1], reverse=True)
            
            # Process top scoring URLs first
            for url, score in scored_urls[:10]:
                if url not in processed_urls:
                    siren, siret, emails = extract_siren_siret_from_page(url)
                    all_siren.update(siren)
                    all_siret.update(siret)
                    all_emails.update(emails)
                    processed_urls.add(url)
                    
        # If no results yet, try crawling
        if not (all_siren or all_siret or all_emails):
            logger.info("No results from sitemap, starting crawl")
            urls = crawl_site(base_url, max_depth=2, max_pages=20)
            
            # Score and sort URLs
            scored_urls = [(url, score_url(url)) for url in urls]
            scored_urls.sort(key=lambda x: x[1], reverse=True)
            
            # Process top scoring URLs
            for url, score in scored_urls[:10]:
                if url not in processed_urls:
                    siren, siret, emails = extract_siren_siret_from_page(url)
                    all_siren.update(siren)
                    all_siret.update(siret)
                    all_emails.update(emails)
                    processed_urls.add(url)
                    
        # If still no results, try browser-based fetching for the homepage
        if not (all_siren or all_siret or all_emails):
            logger.info("No results from crawl, trying browser-based fetch")
            content = fetch_url_with_browser(base_url)
            if content:
                siren, siret, emails = extract_siren_siret_from_page(base_url, content)
                all_siren.update(siren)
                all_siret.update(siret)
                all_emails.update(emails)
                
    except Exception as e:
        logger.error(f"Error processing domain {domain}: {str(e)}")
        
    return all_siren, all_siret, all_emails

def get_urls_from_sitemap(sitemap_url: str) -> List[str]:
    """
    Extrait les URLs d'un sitemap avec meilleure gestion des erreurs.
    """
    try:
        response = requests.get(
            sitemap_url,
            headers=HEADERS,
            verify=False,
            timeout=(CONNECT_TIMEOUT, TIMEOUT)
        )
        response.raise_for_status()
        
        # Essaie de parser comme un sitemap standard
        try:
            tree = etree.fromstring(response.content)
            ns = {'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
            
            # Cherche les URLs dans le sitemap
            urls = []
            
            # Pour les sitemaps standards
            for loc in tree.xpath('.//sm:loc/text()', namespaces=ns):
                urls.append(loc.strip())
                
            # Pour les index de sitemaps
            for child_sitemap in tree.xpath('.//sm:sitemap/sm:loc/text()', namespaces=ns):
                child_urls = get_urls_from_sitemap(child_sitemap.strip())
                urls.extend(child_urls)
                
            return urls
            
        except etree.XMLSyntaxError:
            # Si ce n'est pas un XML valide, essaie de trouver les URLs avec regex
            urls = re.findall(r'<loc>(.*?)</loc>', response.text)
            if urls:
                return urls
                
            # Si toujours rien, essaie de trouver des URLs simples
            urls = re.findall(r'https?://[^\s<>"]+?(?<![\.,])', response.text)
            if urls:
                return urls
    
    except Exception as e:
        logger.error(f"Error fetching sitemap {sitemap_url}: {e}")
        
    return []


def get_clean_text(tree) -> str:
    """
    Extrait et nettoie le texte d'un document HTML.
    """
    texts = []
    
    # Texte des balises meta
    meta_tags = [
        '//meta[@name="description"]/@content',
        '//meta[@property="og:description"]/@content',
        '//meta[@name="keywords"]/@content'
    ]
    for xpath in meta_tags:
        texts.extend(tree.xpath(xpath))
    
    # Texte du footer (souvent contient les mentions légales)
    footer_tags = [
        '//footer//text()',
        '//*[contains(@class, "footer")]//text()',
        '//*[contains(@id, "footer")]//text()'
    ]
    for xpath in footer_tags:
        texts.extend(tree.xpath(xpath))
    
    # Texte des sections qui peuvent contenir des infos légales
    legal_keywords = [
        'legal', 'mention', 'contact', 'about', 'apropos',
        'societe', 'entreprise', 'cgv', 'condition'
    ]
    for keyword in legal_keywords:
        texts.extend(tree.xpath(f'//*[contains(@class, "{keyword}")]//text()'))
        texts.extend(tree.xpath(f'//*[contains(@id, "{keyword}")]//text()'))
    
    # Tout le texte visible
    texts.extend(tree.xpath('//text()'))
    
    # Nettoie le texte
    text = ' '.join(texts)
    text = re.sub(r'\s+', ' ', text)
    text = text.strip()
    
    # Supprime les caractères non-imprimables
    text = ''.join(char for char in text if char.isprintable())
    
    return text


def extract_siren_siret_from_page(url: str, content: str = None) -> Tuple[List[str], List[str], List[str]]:
    """Extrait les numéros SIREN, SIRET et emails d'une page web.
    
    Args:
        url (str): L'URL de la page à analyser
        content (str, optional): Le contenu HTML de la page. Si None, le contenu sera téléchargé.
        
    Returns:
        Tuple[List[str], List[str], List[str]]: Les ensembles de SIREN, SIRET et emails trouvés
    """
    try:
        if content is None:
            # Try regular request first
            try:
                response = requests.get(url, verify=False, timeout=30)
                if response.status_code == 200:
                    content = response.text
                else:
                    logger.info(f"Regular request failed for {url}, trying with browser")
                    content = fetch_url_with_browser(url)
            except Exception as e:
                logger.info(f"Regular request failed for {url}, trying with browser: {str(e)}")
                content = fetch_url_with_browser(url)
            
            if not content:
                return set(), set(), set()
        
        # Parse le HTML avec BeautifulSoup
        soup = BeautifulSoup(content, 'html.parser')
        text = soup.get_text()
        
        # Extrait les numéros et emails
        sirens, sirets = extract_siren_siret(text)
        emails = extract_emails(text)
        
        return sirens, sirets, emails
        
    except Exception as e:
        logger.error(f"Error extracting information from {url}: {str(e)}")
        return set(), set(), set()

def crawl_internal_links(base_url):
    candidates = []
    if not base_url:
        return candidates

    response = cached_fetch(base_url)
    if not (response and response.status_code == 200):
        return candidates

    doc = html.fromstring(response.content)
    links = doc.xpath('//a[@href]')
    visited = set()

    def is_internal_link(link):
        parsed_base = urlparse(base_url)
        parsed_link = urlparse(link)
        return parsed_link.netloc == "" or parsed_link.netloc == parsed_base.netloc

    normalized_keywords = [normalize_text(k) for k in CANDIDATE_KEYWORDS]

    for link in links:
        href = link.get('href')
        if href:
            full_url = urljoin(base_url, href)
            if is_internal_link(full_url) and full_url not in visited:
                visited.add(full_url)
                norm_url = normalize_text(full_url)
                # Filtre de priorisation sur les mots-clés
                if any(keyword in norm_url for keyword in normalized_keywords):
                    candidates.append(full_url)

    return candidates


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
    
    if len(sys.argv) != 3:
        print("Usage: python siret_extractor.py input.csv output.csv")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    with open(input_file, 'r', encoding='utf-8') as f_in, \
         open(output_file, 'w', newline='', encoding='utf-8') as f_out:
        
        reader = csv.DictReader(f_in)
        writer = csv.DictWriter(f_out, fieldnames=['domain', 'siren', 'siret', 'email'])
        writer.writeheader()

        for row in reader:
            domain = row['domain'].strip()
            if not domain:
                continue

            logger.info(f"Processing domain: {domain}")
            sirens, sirets, emails = process_domain(domain)
            
            if not (sirens or sirets or emails):
                logger.warning(f"No SIREN/SIRET/email found for domain: {domain}")
                writer.writerow({'domain': domain, 'siren': '', 'siret': '', 'email': ''})
            else:
                for siren in sirens:
                    for siret in sirets:
                        for email in (emails or ['']):
                            writer.writerow({
                                'domain': domain,
                                'siren': siren,
                                'siret': siret,
                                'email': email
                            })

    logger.info(f"Results written to {output_file}")
    print("\n\x1b[32mExtraction Completed Successfully!\x1b[0m\n")
