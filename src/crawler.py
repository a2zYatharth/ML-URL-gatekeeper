import asyncio
import json
from playwright.async_api import async_playwright
import urllib.parse

class DynamicCrawler:
    def __init__(self, target_url):
        self.raw_url = target_url
        self.normalized_url = self._normalize_url(target_url)
        self.network_traffic = []

    def _normalize_url(self, url):
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    async def run(self):
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            page.on("request", lambda request: self.network_traffic.append({"url": request.url}))
            try:
                await page.goto(self.normalized_url, wait_until="domcontentloaded", timeout=15000)
                await page.wait_for_timeout(5000)
                dom_content = await page.content()
                return dom_content, self.network_traffic
            except Exception as e:
                print(f"[-] Crawl failed: {str(e)}")
                return None, None
            finally:
                await browser.close()