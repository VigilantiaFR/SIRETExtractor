"""
Module principal de l'extracteur SIRET/SIREN.

Ce module contient la logique principale du programme et gère le traitement
des fichiers CSV d'entrée/sortie.
"""

import os
import csv
import sys
import logging
import psutil
import argparse
from datetime import datetime
from logging.handlers import RotatingFileHandler
from fetch_utils import guess_base_url, crawl_internal_links, get_retry_config
from parsing_utils import (
    extract_sitemap_url,
    parse_sitemap,
    filter_candidate_urls,
    extract_siren_siret_from_page,
    score_url
)
import threading
import concurrent.futures
from typing import List, Tuple, Dict
import asyncio
import aiohttp
from aiohttp import ClientTimeout
from urllib.parse import urljoin, urlparse

# Configuration du logger
def setup_logger():
    """Configure le système de logging avec sortie console et fichier."""
    logger = logging.getLogger("SIRETExtractor")
    logger.setLevel(logging.DEBUG)
    
    # Formatter pour les logs
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s :: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Handler pour la console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    
    # Handler pour le fichier
    log_file = 'scraper.log'
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10*1024*1024,  # 10 MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # Nettoyage des handlers existants
    logger.handlers = []
    
    # Ajout des handlers
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger

# Initialisation du logger
logger = setup_logger()

class Stats:
    """Classe pour suivre les statistiques d'exécution"""
    def __init__(self):
        self.start_time = datetime.now()
        self.siren_count = 0
        self.siret_count = 0
        self.email_count = 0
        self.legal_pages_count = 0
        self.error_count = 0
        self.total_requests = 0
        self.process = psutil.Process()
        self.initial_memory = self.process.memory_info().rss
        self._lock = threading.Lock()  # Pour thread-safety
        
    def log_error(self):
        """Incrémente le compteur d'erreurs"""
        with self._lock:
            self.error_count += 1
        
    def log_request(self):
        """Incrémente le compteur de requêtes"""
        with self._lock:
            self.total_requests += 1
        
    def add_siren(self, count):
        """Ajoute des SIREN trouvés"""
        with self._lock:
            self.siren_count += count
        
    def add_siret(self, count):
        """Ajoute des SIRET trouvés"""
        with self._lock:
            self.siret_count += count
        
    def add_emails(self, count):
        """Ajoute des emails trouvés"""
        with self._lock:
            self.email_count += count
        
    def add_legal_page(self):
        """Incrémente le compteur de pages légales"""
        with self._lock:
            self.legal_pages_count += 1
        
    def get_stats(self):
        """Retourne les statistiques d'exécution"""
        with self._lock:
            end_time = datetime.now()
            duration = end_time - self.start_time
            current_memory = self.process.memory_info().rss
            memory_usage = (current_memory - self.initial_memory) / 1024 / 1024  # En MB
            
            error_rate = (self.error_count / self.total_requests * 100) if self.total_requests > 0 else 0
            
            return {
                'duration': str(duration),
                'siren_count': self.siren_count,
                'siret_count': self.siret_count,
                'email_count': self.email_count,
                'legal_pages_count': self.legal_pages_count,
                'memory_usage': f"{memory_usage:.2f} MB",
                'error_rate': f"{error_rate:.2f}%",
                'total_requests': self.total_requests
            }
        
    def print_stats(self):
        """Affiche les statistiques d'exécution"""
        stats = self.get_stats()
        print("\n" + "="*50)
        print("STATISTIQUES D'EXÉCUTION")
        print("="*50)
        print(f"Temps total d'exécution: {stats['duration']}")
        print(f"Nombre de SIREN trouvés: {stats['siren_count']}")
        print(f"Nombre de SIRET trouvés: {stats['siret_count']}")
        print(f"Nombre d'emails trouvés: {stats['email_count']}")
        print(f"Nombre de pages mentions légales: {stats['legal_pages_count']}")
        print(f"Utilisation mémoire: {stats['memory_usage']}")
        print(f"Taux d'erreur: {stats['error_rate']}")
        print(f"Nombre total de requêtes: {stats['total_requests']}")
        print("="*50)

# Variable globale pour les statistiques
stats = Stats()

async def fetch_url_async(session: aiohttp.ClientSession, url: str) -> Tuple[str, str]:
    """
    Récupère une URL de manière asynchrone.
    """
    try:
        async with session.get(url, ssl=False) as response:
            if response.status == 200:
                return url, await response.text()
            else:
                logger.error(f"Error {response.status} fetching {url}")
                return url, ""
    except Exception as e:
        logger.error(f"Error fetching {url}: {e}")
        return url, ""

async def process_urls_async(urls: List[str], max_concurrent: int = 100) -> Dict[str, str]:
    """
    Traite une liste d'URLs de manière asynchrone.
    """
    timeout = ClientTimeout(total=30)
    connector = aiohttp.TCPConnector(limit=max_concurrent, ssl=False)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [fetch_url_async(session, url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {url: content for url, content in results if content}

def process_domain(domain: str) -> tuple:
    """
    Traite un domaine pour extraire les SIRET et emails.
    
    Args:
        domain (str): Le domaine à traiter
        
    Returns:
        tuple: (status, error_reason, base_url, sirens, sirets, emails)
    """
    try:
        # Trouver l'URL de base qui fonctionne
        base_url = guess_base_url(domain)
        stats.log_request()
        
        if not base_url:
            return "error", "Could not determine base URL", None, None, None, None
            
        logger.info(f"Found working base URL: {base_url}")
        
        # Récupérer les URLs candidates
        sitemap_url = extract_sitemap_url(base_url)
        stats.log_request()
        
        urls = []
        if sitemap_url:
            urls = parse_sitemap(sitemap_url)
            if not urls:
                logger.warning(f"No URLs found in sitemap for {domain}, falling back to crawler")
                urls = crawl_internal_links(base_url)
        else:
            logger.info(f"No sitemap found for {domain}, using crawler")
            urls = crawl_internal_links(base_url)
            
        # Filtre et score les URLs
        candidate_urls = []
        for url in urls:
            if isinstance(url, str) and score_url(url) > 1.0:
                candidate_urls.append(url)
                if any(keyword in url.lower() for keyword in ['mentions', 'legal']):
                    stats.add_legal_page()
        
        if not candidate_urls:
            logger.warning(f"No candidate URLs found for {domain}")
            
            # Essayer l'URL de base directement
            candidate_urls = [base_url]
        
        # Initialiser les ensembles pour stocker les résultats
        all_sirens = set()
        all_sirets = set()
        all_emails = set()
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(process_urls_async(candidate_urls))
        
        for url, content in results.items():
            try:
                # Extraire les informations de la page
                page_sirens, page_sirets, page_emails = extract_siren_siret_from_page(url, content)
                
                # Ajouter aux résultats globaux
                all_sirens.update(page_sirens)
                all_sirets.update(page_sirets)
                all_emails.update(page_emails)
                
            except Exception as e:
                logger.error(f"Error processing URL {url}: {e}")
                continue
                
        # Mise à jour des statistiques
        stats.add_siren(len(all_sirens))
        stats.add_siret(len(all_sirets))
        stats.add_emails(len(all_emails))
        
        if not (all_sirens or all_sirets or all_emails):
            logger.warning(f"No SIREN/SIRET/email found for domain: {domain}")
            
        return "success", None, base_url, list(all_sirens), list(all_sirets), list(all_emails)
        
    except Exception as e:
        logger.error(f"Error processing domain {domain}: {e}")
        stats.log_error()
        return "error", str(e), None, None, None, None

def process_domains_parallel(domains: List[str], max_workers: int = 10) -> List[Tuple]:
    """
    Traite plusieurs domaines en parallèle.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        return list(executor.map(process_domain, domains))

def parse_args():
    """Parse les arguments de la ligne de commande"""
    parser = argparse.ArgumentParser(description='SIRET Extractor - Web Scraper')
    parser.add_argument('input_file', help='Fichier CSV contenant la liste des domaines')
    parser.add_argument('output_file', help='Fichier CSV de sortie')
    parser.add_argument('--max-retries', type=int, help='Nombre maximum de tentatives par requête')
    parser.add_argument('--max-backoff', type=int, help='Délai maximum entre les tentatives (secondes)')
    return parser.parse_args()

def print_cyberpunk_banner():
    """Affiche une bannière stylisée"""
    print("\n    ===============================================")
    print("                SIRET EXTRACTOR v2.0               ")
    print("             [ Powered by Vigilantia ]             ")
    print("    ===============================================\n")

def main():
    """Point d'entrée principal du programme."""
    print_cyberpunk_banner()
    print(f"Starting extraction at {datetime.now()}\n")
    
    args = parse_args()
    
    # Configuration du retry avec les arguments CLI
    os.environ["MAX_RETRIES"] = str(args.max_retries)
    os.environ["MAX_BACKOFF"] = str(args.max_backoff)
    
    # Lecture du fichier d'entrée
    domains = []
    with open(args.input_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        domains = [row['domain'] for row in reader if row.get('domain')]
    
    total_rows = len(domains)
    logger.info(f"Found {total_rows} domains to process")
    
    # Traitement parallèle des domaines
    results = process_domains_parallel(domains)
    
    # Écriture des résultats
    with open(args.output_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['domain', 'status', 'error_reason', 'base_url', 'siren', 'siret', 'emails']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for i, (domain, result) in enumerate(zip(domains, results), 1):
            status, error_reason, base_url, sirens, sirets, emails = result
            
            writer.writerow({
                'domain': domain,
                'status': status,
                'error_reason': error_reason,
                'base_url': base_url,
                'siren': ';'.join(sorted(sirens)) if sirens else '',
                'siret': ';'.join(sorted(sirets)) if sirets else '',
                'emails': ';'.join(sorted(emails)) if emails else ''
            })
            
    # Affichage des statistiques
    stats.print_stats()

if __name__ == "__main__":
    main()
