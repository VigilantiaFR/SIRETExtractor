"""
Module pour la récupération de contenu via un navigateur headless.

Ce module utilise Playwright pour récupérer le contenu des pages web,
y compris le contenu généré par JavaScript.
"""

import asyncio
from playwright.async_api import async_playwright
import logging

logger = logging.getLogger("SIRETextractor")

async def _fetch_with_browser(url: str, timeout: int = 30000) -> str:
    """
    Récupère le contenu d'une page web en utilisant un navigateur headless.
    
    Args:
        url (str): L'URL à récupérer
        timeout (int): Timeout en millisecondes
        
    Returns:
        str: Le contenu HTML de la page
    """
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            context = await browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            )
            page = await context.new_page()
            
            # Configure timeout
            page.set_default_timeout(timeout)
            
            # Navigate to the page
            await page.goto(url, wait_until='networkidle')
            
            # Wait for the content to be loaded
            await page.wait_for_load_state('domcontentloaded')
            
            # Get the full HTML content
            content = await page.content()
            
            return content
            
        except Exception as e:
            logger.error(f"Error fetching {url} with browser: {str(e)}")
            return ""
        finally:
            await browser.close()

def fetch_url_with_browser(url: str, timeout: int = 30000) -> str:
    """
    Version synchrone de _fetch_with_browser.
    
    Args:
        url (str): L'URL à récupérer
        timeout (int): Timeout en millisecondes
        
    Returns:
        str: Le contenu HTML de la page
    """
    try:
        return asyncio.run(_fetch_with_browser(url, timeout))
    except Exception as e:
        logger.error(f"Error in fetch_url_with_browser for {url}: {str(e)}")
        return ""
