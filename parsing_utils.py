"""
Utilitaires pour l'analyse et l'extraction de données.

Ce module contient les fonctions nécessaires pour extraire les numéros SIRET/SIREN
et autres informations pertinentes des pages web.
"""

import os
import re
import logging
from lxml import etree, html
import unicodedata
from fetch_utils import fetch_url
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

logger = logging.getLogger("SIRETExtractor")

# Patterns for SIREN, SIRET and Email
SIREN_PATTERN = r'\b(\d{3}\s?\d{3}\s?\d{3})\b'
SIRET_PATTERN = r'\b(\d{3}\s?\d{3}\s?\d{3}\s?\d{5})\b'
EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

# Mots-clés prioritaires pour les pages légales
LEGAL_KEYWORDS = [
    "mentionslegales", "mentions-legales", "mentions_legales", "mentions-légales",
    "mentions_légales", "mentionslégales", "legal-notice", "legal_notice",
    "legalnotice", "legal", "legales", "légales"
]

# Mots-clés secondaires pour les autres pages pertinentes
SECONDARY_KEYWORDS = [
    "contact", "about", "a-propos", "apropos", "about-us", "aboutus",
    "infos", "informations", "cgu", "cgv", "privacy", "policy",
    "terms", "conditions", "impressum", "rgpd", "gdpr"
]

class ScoredLink:
    def __init__(self, url, score):
        self.url = url
        self.score = score

def normalize_text(text: str) -> str:
    """
    Normalise le texte en supprimant les accents et en convertissant en minuscules.
    
    Args:
        text (str): Le texte à normaliser
        
    Returns:
        str: Le texte normalisé
    """
    return ''.join(c for c in unicodedata.normalize('NFD', text) if not unicodedata.combining(c)).lower()

def normalize_url(url: str) -> str:
    """
    Normalise une URL en retirant les caractères spéciaux et en la convertissant en minuscules.
    
    Args:
        url (str): L'URL à normaliser
        
    Returns:
        str: L'URL normalisée
    """
    # Extrait le chemin de l'URL
    path = urlparse(url).path.strip('/')
    # Normalise le texte
    return normalize_text(path)

def score_url(url: str) -> int:
    """
    Attribue un score à une URL en fonction de sa pertinence.
    
    Args:
        url (str): L'URL à scorer
        
    Returns:
        int: Le score de la URL
    """
    score = 0
    normalized_path = normalize_url(url)
    parsed_url = urlparse(url)
    path_parts = parsed_url.path.lower().split('/')
    
    # Check for localized paths (fr/terms, en/legal, etc.)
    if len(path_parts) >= 2:
        if path_parts[1] in ['fr', 'en'] and any(part in LEGAL_KEYWORDS for part in path_parts[2:]):
            score += 15
    
    # Check for footer links
    if 'footer' in normalized_path and any(keyword in normalized_path for keyword in LEGAL_KEYWORDS):
        score += 12
    
    # Check for direct legal notice pages
    if any(keyword in normalized_path for keyword in LEGAL_KEYWORDS):
        score += 10
        
    # Check for secondary keywords
    if any(keyword in normalized_path for keyword in SECONDARY_KEYWORDS):
        score += 5
    
    # Bonus for common file extensions
    if url.lower().endswith(('.html', '.php', '.htm')):
        score += 2
        
    # Penalty for obviously irrelevant pages
    if any(x in normalized_path for x in ['blog', 'article', 'news', 'post']):
        score -= 5
        
    return score

def extract_links_from_html(html_content: str, base_url: str) -> list:
    """
    Extrait les liens d'une page HTML en se concentrant sur les liens pertinents.
    
    Args:
        html_content (str): Le contenu HTML à analyser
        base_url (str): L'URL de base pour résoudre les liens relatifs
        
    Returns:
        list: Liste des liens pertinents
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    links = set()
    
    # Extract links from footer first (higher priority)
    footer_tags = soup.find_all(['footer', 'div'], class_=lambda x: x and any(word in x.lower() for word in ['footer', 'bottom', 'bas-page']))
    for footer in footer_tags:
        for a in footer.find_all('a', href=True):
            href = a.get('href', '').strip()
            if href and not href.startswith(('#', 'javascript:', 'tel:', 'mailto:')):
                full_url = urljoin(base_url, href)
                links.add(full_url)
    
    # Then look for links in the rest of the page
    for a in soup.find_all('a', href=True):
        href = a.get('href', '').strip()
        if href and not href.startswith(('#', 'javascript:', 'tel:', 'mailto:')):
            # Check if link text or title contains relevant keywords
            text = (a.get_text() + ' ' + a.get('title', '')).lower()
            if any(keyword in text for keyword in LEGAL_KEYWORDS + SECONDARY_KEYWORDS):
                full_url = urljoin(base_url, href)
                links.add(full_url)
    
    return list(links)

def filter_candidate_urls(urls: list) -> list:
    """
    Filtre et trie les URLs candidates par pertinence.
    
    Args:
        urls (list): Liste des URLs à filtrer
        
    Returns:
        list: Liste triée des URLs les plus pertinentes
    """
    scored_urls = []
    
    for url in urls:
        score = score_url(url)
        if score > 0:
            scored_urls.append(ScoredLink(url, score))
            
    # Tri par score décroissant
    return [link.url for link in sorted(scored_urls, key=lambda x: x.score, reverse=True)]

def extract_sitemap_url(base_url: str) -> str:
    """
    Extrait l'URL du sitemap depuis robots.txt ou utilise l'emplacement par défaut.
    
    Args:
        base_url (str): L'URL de base du site
        
    Returns:
        str: L'URL du sitemap ou None si non trouvé
    """
    try:
        robots_url = urljoin(base_url, '/robots.txt')
        status_code, content = fetch_url(robots_url)
        
        if status_code == 200 and content:
            # Cherche l'URL du sitemap dans robots.txt
            for line in content.splitlines():
                if line.lower().startswith('sitemap:'):
                    sitemap_url = line.split(':', 1)[1].strip()
                    logger.info(f"Found sitemap URL in robots.txt: {sitemap_url}")
                    return sitemap_url
                    
        # Si pas trouvé dans robots.txt, essaie l'emplacement par défaut
        logger.warning(f"No sitemap entry found in robots.txt for {base_url}")
        logger.info(f"Using default sitemap location: {base_url}/sitemap.xml")
        return urljoin(base_url, '/sitemap.xml')
        
    except Exception as e:
        logger.warning(f"Could not fetch robots.txt from {base_url}: {str(e)}")
        logger.info(f"Falling back to default sitemap location for {base_url}")
        return urljoin(base_url, '/sitemap.xml')

def parse_sitemap(sitemap_url: str) -> list:
    """
    Parse un fichier sitemap XML pour extraire les URLs.
    
    Args:
        sitemap_url (str): L'URL du sitemap à parser
        
    Returns:
        list: Liste des URLs trouvées dans le sitemap
    """
    try:
        status_code, content = fetch_url(sitemap_url)
        if not status_code == 200 or not content:
            logger.warning(f"HTTP error for {sitemap_url}: {status_code}")
            return []
            
        # Parse le XML
        try:
            root = etree.fromstring(content.encode())
        except etree.XMLSyntaxError:
            logger.warning(f"Invalid XML in sitemap: {sitemap_url}")
            return []
            
        # Extrait les URLs du sitemap
        namespaces = {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
        urls = []
        
        # Vérifie si c'est un sitemap index
        if root.tag.endswith('sitemapindex'):
            for sitemap in root.findall('.//ns:loc', namespaces):
                sub_urls = parse_sitemap(sitemap.text)
                urls.extend(sub_urls)
        else:
            urls = [url.text for url in root.findall('.//ns:loc', namespaces)]
            
        return urls
        
    except Exception as e:
        logger.error(f"Error parsing sitemap {sitemap_url}: {str(e)}")
        return []

def extract_siren_siret_from_page(url: str, content: str = None) -> tuple:
    """
    Extrait les numéros SIREN/SIRET et emails d'une page web.
    
    Args:
        url (str): L'URL de la page à analyser
        content (str, optional): Le contenu HTML de la page. Si None, le contenu sera téléchargé.
        
    Returns:
        tuple: (siren, siret, emails) - Ensembles des numéros et emails trouvés
    """
    try:
        if content is None:
            status_code, content = fetch_url(url)
            if not status_code == 200 or not content:
                return set(), set(), set()
            
        # Parse le HTML
        soup = BeautifulSoup(content, 'html.parser')
        text = soup.get_text()
        
        # Extrait les numéros et emails
        siren = extract_siren_from_text(text)
        siret = extract_siret_from_text(text)
        emails = extract_emails_from_text(text)
        
        return siren, siret, emails
        
    except Exception as e:
        logger.error(f"Error extracting information from {url}: {str(e)}")
        return set(), set(), set()

def extract_siren_siret_from_text(text: str) -> tuple:
    """
    Extrait les numéros SIREN, SIRET et emails d'un texte.
    
    Args:
        text (str): Le texte à analyser
        
    Returns:
        tuple: (set de SIREN, set de SIRET, set d'emails)
    """
    try:
        ignored_numbers = set(os.environ.get("IGNORED_NUMBERS", "").split(','))
        
        # Clean text
        text = text.replace('\n', ' ').replace('\t', ' ')
        
        # Extract numbers
        siren_matches = set(re.findall(SIREN_PATTERN, text))
        siret_matches = set(re.findall(SIRET_PATTERN, text))
        email_matches = set(re.findall(EMAIL_PATTERN, text))
        
        # Filter out ignored numbers
        siren_matches = {num.replace(' ', '') for num in siren_matches if num.replace(' ', '') not in ignored_numbers}
        siret_matches = {num.replace(' ', '') for num in siret_matches if num.replace(' ', '') not in ignored_numbers}
        
        logger.debug(f"Found {len(siren_matches)} SIREN, {len(siret_matches)} SIRET, {len(email_matches)} emails")
        return siren_matches, siret_matches, email_matches
        
    except Exception as e:
        logger.error(f"Error extracting numbers from text: {str(e)}")
        return set(), set(), set()

def extract_siren_from_text(text: str) -> set:
    """
    Extrait les numéros SIREN d'un texte.
    
    Args:
        text (str): Le texte à analyser
        
    Returns:
        set: Ensemble des numéros SIREN trouvés
    """
    try:
        ignored_numbers = set(os.environ.get("IGNORED_NUMBERS", "").split(','))
        
        # Clean text
        text = text.replace('\n', ' ').replace('\t', ' ')
        
        # Extract numbers
        siren_matches = set(re.findall(SIREN_PATTERN, text))
        
        # Filter out ignored numbers
        siren_matches = {num.replace(' ', '') for num in siren_matches if num.replace(' ', '') not in ignored_numbers}
        
        logger.debug(f"Found {len(siren_matches)} SIREN")
        return siren_matches
        
    except Exception as e:
        logger.error(f"Error extracting SIREN from text: {str(e)}")
        return set()

def extract_siret_from_text(text: str) -> set:
    """
    Extrait les numéros SIRET d'un texte.
    
    Args:
        text (str): Le texte à analyser
        
    Returns:
        set: Ensemble des numéros SIRET trouvés
    """
    try:
        ignored_numbers = set(os.environ.get("IGNORED_NUMBERS", "").split(','))
        
        # Clean text
        text = text.replace('\n', ' ').replace('\t', ' ')
        
        # Extract numbers
        siret_matches = set(re.findall(SIRET_PATTERN, text))
        
        # Filter out ignored numbers
        siret_matches = {num.replace(' ', '') for num in siret_matches if num.replace(' ', '') not in ignored_numbers}
        
        logger.debug(f"Found {len(siret_matches)} SIRET")
        return siret_matches
        
    except Exception as e:
        logger.error(f"Error extracting SIRET from text: {str(e)}")
        return set()

def extract_emails_from_text(text: str) -> set:
    """
    Extrait les emails d'un texte.
    
    Args:
        text (str): Le texte à analyser
        
    Returns:
        set: Ensemble des emails trouvés
    """
    try:
        # Clean text
        text = text.replace('\n', ' ').replace('\t', ' ')
        
        # Extract emails
        email_matches = set(re.findall(EMAIL_PATTERN, text))
        
        logger.debug(f"Found {len(email_matches)} emails")
        return email_matches
        
    except Exception as e:
        logger.error(f"Error extracting emails from text: {str(e)}")
        return set()
