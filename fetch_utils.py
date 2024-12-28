"""
Utilitaires pour la récupération de données HTTP et le crawling de sites web.

Ce module contient les fonctions nécessaires pour effectuer des requêtes HTTP,
gérer les caches de requêtes et explorer les sites web.
"""

import os
import re
import logging
import warnings
import urllib3
import requests
from bs4 import BeautifulSoup
from collections import deque
from functools import lru_cache
from urllib.parse import urljoin, urlparse
from tenacity import retry, stop_after_attempt, wait_exponential
from lxml import html
import tenacity

# Désactive les avertissements SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("SIRETExtractor")

# Configuration
CONNECT_TIMEOUT = int(os.environ.get("CONNECT_TIMEOUT", "10"))
TIMEOUT = int(os.environ.get("TIMEOUT", "30"))
MAX_RETRIES = int(os.environ.get("MAX_RETRIES", "5"))
MAX_BACKOFF = int(os.environ.get("MAX_BACKOFF", "10"))

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1"
}

# Mots-clés pour la détection des pages légales
LEGAL_KEYWORDS = {
    'mentions légales': 1.0,
    'mentions-legales': 1.0,
    'legal': 0.8,
    'legal-notice': 0.8,
    'cgv': 0.7,
    'conditions générales': 0.7,
    'conditions-generales': 0.7,
    'politique de confidentialité': 0.6,
    'confidentialite': 0.6,
    'privacy': 0.6,
    'terms': 0.5,
    'about': 0.4,
    'contact': 0.3
}

class ScoredLink:
    """Classe pour stocker un lien avec son score de pertinence"""
    def __init__(self, url, score=0.0, depth=0):
        self.url = url
        self.score = score
        self.depth = depth
        
    def __lt__(self, other):
        return self.score > other.score  # Tri décroissant
        
def get_retry_config():
    """
    Retourne un décorateur de retry avec la configuration spécifiée.
    """
    return retry(
        stop=stop_after_attempt(MAX_RETRIES),
        wait=wait_exponential(multiplier=1, min=4, max=MAX_BACKOFF),
        reraise=True
    )

def score_url(url, text=None):
    """
    Calcule un score de pertinence pour une URL et son texte.
    
    Args:
        url (str): L'URL à évaluer
        text (str): Le texte du lien (optionnel)
        
    Returns:
        float: Score de pertinence entre 0 et 1
    """
    score = 0.0
    url_lower = url.lower()
    
    # Score basé sur l'URL
    for keyword, weight in LEGAL_KEYWORDS.items():
        if keyword in url_lower:
            score = max(score, weight)
            
    # Score basé sur le texte du lien si disponible
    if text:
        text_lower = text.lower()
        for keyword, weight in LEGAL_KEYWORDS.items():
            if keyword in text_lower:
                score = max(score, weight * 1.2)  # Bonus pour le texte
                
    # Bonus pour les URLs courtes et propres
    path_length = len(urlparse(url).path.split('/'))
    if path_length <= 2:  # /mentions-legales ou /legal
        score *= 1.2
        
    return score

def extract_footer_links(soup, base_url):
    """
    Extrait les liens du footer avec leurs scores.
    
    Args:
        soup (BeautifulSoup): Le contenu HTML parsé
        base_url (str): L'URL de base pour résoudre les liens relatifs
        
    Returns:
        list: Liste de ScoredLink trouvés dans le footer
    """
    footer_links = []
    
    # Cherche le footer avec différents sélecteurs
    footer_tags = soup.find_all(['footer', 'div'], class_=lambda x: x and ('footer' in x.lower()))
    
    for footer in footer_tags:
        for link in footer.find_all('a', href=True):
            href = link['href']
            if not href.startswith(('http', 'https', 'mailto', 'tel', '#')):
                href = urljoin(base_url, href)
                
            if urlparse(href).netloc == urlparse(base_url).netloc:
                score = score_url(href, link.get_text(strip=True))
                footer_links.append(ScoredLink(href, score))
                
    return sorted(footer_links)  # Tri par score décroissant

def crawl_internal_links(base_url, max_depth=2):
    """
    Récupère tous les liens internes d'une page web avec un BFS limité.
    
    Args:
        base_url (str): L'URL de base à crawler
        max_depth (int): Profondeur maximale du crawl
        
    Returns:
        list: Liste de ScoredLink triés par pertinence
    """
    try:
        status_code, content = fetch_url(base_url)
        if not content:
            return []
            
        soup = BeautifulSoup(content, 'html.parser')
        base_domain = urlparse(base_url).netloc
        
        # 1. Analyse du footer en priorité
        footer_links = extract_footer_links(soup, base_url)
        if footer_links:
            logger.info(f"Found {len(footer_links)} links in footer for {base_url}")
            
        # 2. BFS pour le reste des liens
        visited = {link.url for link in footer_links}
        visited.add(base_url)
        
        queue = deque([(base_url, 0)])  # (url, depth)
        all_links = footer_links.copy()
        
        while queue and len(visited) < 100:  # Limite de sécurité
            current_url, depth = queue.popleft()
            
            if depth >= max_depth:
                continue
                
            try:
                status_code, page_content = fetch_url(current_url)
                if not page_content:
                    continue
                    
                page_soup = BeautifulSoup(page_content, 'html.parser')
                
                for link in page_soup.find_all('a', href=True):
                    href = link['href']
                    absolute_url = urljoin(base_url, href)
                    
                    if (urlparse(absolute_url).netloc == base_domain and 
                        absolute_url not in visited and 
                        not href.startswith(('#', 'mailto:', 'tel:'))):
                        
                        visited.add(absolute_url)
                        score = score_url(absolute_url, link.get_text(strip=True))
                        
                        if score > 0:  # Ne garde que les liens pertinents
                            all_links.append(ScoredLink(absolute_url, score, depth + 1))
                            queue.append((absolute_url, depth + 1))
                            
            except Exception as e:
                logger.warning(f"Error crawling {current_url}: {str(e)}")
                continue
                
        # Tri final par score et suppression des doublons
        unique_links = []
        seen_urls = set()
        
        for link in sorted(all_links):
            if link.url not in seen_urls:
                seen_urls.add(link.url)
                unique_links.append(link)
                
        logger.info(f"Found {len(unique_links)} total candidate links for {base_url}")
        return unique_links
        
    except Exception as e:
        logger.error(f"Error in crawl_internal_links for {base_url}: {str(e)}")
        return []

@get_retry_config()
def fetch_url(url: str, timeout: tuple = (CONNECT_TIMEOUT, TIMEOUT)) -> tuple:
    """
    Effectue une requête GET sur l'URL avec une configuration optimisée.
    
    Args:
        url (str): L'URL à récupérer
        timeout (tuple): Tuple de timeouts (connect, read)
        
    Returns:
        tuple: (status_code, content) ou (None, None) en cas d'erreur
    """
    try:
        session = requests.Session()
        session.verify = False
        session.headers.update(HEADERS)
        session.trust_env = False
        
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=MAX_RETRIES,
            pool_block=False
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        try:
            response = session.get(
                url,
                timeout=timeout,
                allow_redirects=True
            )
            response.raise_for_status()
            return response.status_code, response.text
            
        except requests.exceptions.SSLError:
            logger.warning(f"SSL Error for {url}, retrying with HTTP")
            if url.startswith('https://'):
                url_http = url.replace('https://', 'http://')
                response = session.get(
                    url_http,
                    timeout=timeout,
                    allow_redirects=True
                )
                response.raise_for_status()
                return response.status_code, response.text
            raise
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching {url}: {str(e)}")
        return None, None
    finally:
        session.close()

def guess_base_url(domain: str) -> str:
    """
    Devine l'URL de base pour un domaine avec gestion intelligente des variantes.
    
    Args:
        domain (str): Le nom de domaine à tester
        
    Returns:
        str: L'URL de base fonctionnelle ou None si aucune n'est trouvée
    """
    if not domain:
        logger.error("Empty domain provided to guess_base_url")
        return None
        
    domain = domain.lower().strip()
    if domain.startswith(('http://', 'https://')):
        parsed = urlparse(domain)
        domain = parsed.netloc
        
    variants = [
        f"https://www.{domain}",
        f"https://{domain}",
        f"http://www.{domain}",
        f"http://{domain}"
    ]
    
    logger.debug(f"Testing URL variants for domain: {domain}")
    for url in variants:
        try:
            response = fetch_url(url)
            if response and response[0] == 200:
                logger.info(f"Found working base URL: {url}")
                return url
        except Exception as e:
            logger.warning(f"Failed to test variant {url}: {str(e)}")
            continue
            
    logger.error(f"No working base URL found for domain: {domain}")
    return None
