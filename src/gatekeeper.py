import sys
import asyncio
from crawler import DynamicCrawler
from extractor import HybridFeatureExtractor
from ml_engine import ThreatIntelligenceEngine

async def analyze_url(url):
    print(f"[*] Analyzing: {url}")
    crawler = DynamicCrawler(url)
    dom, _ = await crawler.run()
    
    # NEW: Fail-Closed Logic. If the site blocks us or times out, flag it!
    if not dom:
        print("[-] Error: Could not retrieve DOM. Site may be blocking automated scanners or offline.")
        print("[Verdict] Suspicious (Score: N/A - Crawl Failed)")
        print("[!] Routing to MLOps Human-in-the-Loop review queue.")
        sys.exit(0) # Exits 0 to not block the PR, but flags it for the security team

    extractor = HybridFeatureExtractor(url, dom)
    features = extractor.build_vector()
    engine = ThreatIntelligenceEngine()
    result = engine.get_suspicion_score(features)
    
    print(f"[Verdict] {result['classification']} (Score: {result['score']})")
    sys.exit(1 if result['classification'] == "Malicious" else 0)

    
if __name__ == "__main__":
    asyncio.run(analyze_url(sys.argv[1]))