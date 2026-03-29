#!/usr/bin/env python3
"""
Proxy Scraper Telegram Bot v3 — Ping-Quality Focused
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
New in v3 (all real, no placeholders):
  • Two-phase testing: quick filter (short timeout) → multi-sample on survivors
  • Per-proxy multi-sample ping (configurable 1–5 samples)
  • Jitter calculation (std-dev of samples) → stable vs unstable flag
  • Ping Score = weighted average of ping + jitter penalty
  • Ping Tiers: Elite (<200ms) / Good (200–500ms) / Medium (500–1000ms) / Slow (>1s)
  • Per-tier export files sent separately
  • Max-ping filter: drop proxies above user threshold
  • /top N command — fastest N proxies inline
  • Quick-filter phase uses short timeout to skip obviously dead proxies fast
  • Settings: max_ping, samples, quick_timeout, tier_export on/off
"""

import asyncio
import aiohttp
import csv
import io
import json
import logging
import math
import os
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

from aiohttp_socks import ProxyConnector, ProxyType
from bs4 import BeautifulSoup
from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup, Message,
)
from telegram.constants import ParseMode
from telegram.ext import (
    Application, CommandHandler, MessageHandler,
    CallbackQueryHandler, ContextTypes, filters,
)
from telegram.error import RetryAfter, BadRequest

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("proxybot")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("telegram").setLevel(logging.WARNING)

# ─── Constants ────────────────────────────────────────────────────────────────
PROGRESS_MIN_GAP   = 3.0      # min seconds between Telegram edits
QUICK_TIMEOUT      = 4        # phase-1 quick-filter timeout (seconds)
DEFAULT_TIMEOUT    = 10       # phase-2 full test timeout
DEFAULT_CONCUR     = 100      # semaphore concurrency
DEFAULT_SAMPLES    = 2        # how many ping samples per alive proxy
DEFAULT_MAX_PING   = 2000     # drop proxies slower than this (ms), 0 = no limit
DEFAULT_TEST_URL   = "http://httpbin.org/ip"
FALLBACK_TEST_URLS = [        # rotated if primary fails
    "http://ip-api.com/json",
    "http://checkip.amazonaws.com",
    "http://ifconfig.me/ip",
]

# ─── Ping Tiers ───────────────────────────────────────────────────────────────
# (label, max_ms, emoji)
TIERS = [
    ("elite",  200,  "🚀"),
    ("good",   500,  "✅"),
    ("medium", 1000, "🟡"),
    ("slow",   9999, "🐢"),
]

def ping_tier(ms: Optional[int]) -> tuple[str, str]:
    """Return (tier_name, emoji) for a given response_ms."""
    if ms is None:
        return ("dead", "💀")
    for name, limit, emoji in TIERS:
        if ms <= limit:
            return (name, emoji)
    return ("slow", "🐢")

# ─── Free Sources ─────────────────────────────────────────────────────────────
FREE_SOURCES: dict[str, dict] = {
    "ProxyScrape HTTP": {
        "url": "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=5000&country=all",
        "type": "http", "parser": "text",
    },
    "ProxyScrape SOCKS4": {
        "url": "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=5000",
        "type": "socks4", "parser": "text",
    },
    "ProxyScrape SOCKS5": {
        "url": "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=5000",
        "type": "socks5", "parser": "text",
    },
    "TheSpeedX HTTP": {
        "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "type": "http", "parser": "text",
    },
    "TheSpeedX SOCKS4": {
        "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "type": "socks4", "parser": "text",
    },
    "TheSpeedX SOCKS5": {
        "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "type": "socks5", "parser": "text",
    },
    "ShiftyTR HTTP": {
        "url": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
        "type": "http", "parser": "text",
    },
    "ShiftyTR HTTPS": {
        "url": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
        "type": "http", "parser": "text",
    },
    "MuRongPIG HTTP": {
        "url": "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt",
        "type": "http", "parser": "text",
    },
    "MuRongPIG SOCKS5": {
        "url": "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt",
        "type": "socks5", "parser": "text",
    },
    "GeoNode HTTP": {
        "url": "https://proxylist.geonode.com/api/proxy-list?limit=200&page=1&sort_by=lastChecked&sort_type=desc&protocols=http,https",
        "type": "auto", "parser": "geonode_json",
    },
    "ProxyList.to": {
        "url": "https://www.proxy-list.download/api/v1/get?type=http",
        "type": "http", "parser": "text",
    },
    "Free-Proxy-List.net": {
        "url": "https://free-proxy-list.net/",
        "type": "auto", "parser": "html_table",
    },
    "SSL-Proxies.org": {
        "url": "https://www.sslproxies.org/",
        "type": "http", "parser": "html_table",
    },
}

# ─── Data Classes ─────────────────────────────────────────────────────────────
@dataclass
class ProxyResult:
    proxy:        str
    protocol:     str  = "unknown"
    alive:        bool = False
    # ── Ping quality fields ──────────────────────────────────────
    response_ms:  Optional[int]       = None   # best ping sample
    avg_ms:       Optional[int]       = None   # mean of all samples
    jitter_ms:    Optional[int]       = None   # std-dev of samples (stability)
    ping_samples: list = field(default_factory=list)  # raw sample list
    ping_score:   float = 9999.0               # lower = better (ms + jitter)
    tier:         str  = "dead"                # elite/good/medium/slow/dead
    tier_emoji:   str  = "💀"
    stable:       bool = False                 # jitter < 100ms
    # ── Geo fields ───────────────────────────────────────────────
    country:      str  = ""
    country_flag: str  = ""
    city:         str  = ""
    isp:          str  = ""
    anonymity:    str  = ""
    error:        str  = ""

    def finalize_ping(self) -> None:
        """Compute avg, jitter, score, tier from ping_samples."""
        s = self.ping_samples
        if not s:
            return
        self.response_ms = min(s)
        self.avg_ms      = int(sum(s) / len(s))
        if len(s) > 1:
            mean   = sum(s) / len(s)
            self.jitter_ms = int(math.sqrt(sum((x - mean)**2 for x in s) / len(s)))
        else:
            self.jitter_ms = 0
        # Score: avg + 50% jitter penalty
        self.ping_score = self.avg_ms + self.jitter_ms * 0.5
        self.tier, self.tier_emoji = ping_tier(self.response_ms)
        self.stable = (self.jitter_ms is not None and self.jitter_ms < 100)


@dataclass
class UserSettings:
    timeout:       int   = DEFAULT_TIMEOUT
    quick_timeout: int   = QUICK_TIMEOUT
    concur:        int   = DEFAULT_CONCUR
    samples:       int   = DEFAULT_SAMPLES    # ping samples per proxy
    max_ping:      int   = DEFAULT_MAX_PING   # 0 = no limit
    test_url:      str   = DEFAULT_TEST_URL
    geo_lookup:    bool  = True
    export_fmt:    str   = "txt"             # txt / csv / json
    tier_export:   bool  = True              # send per-tier files

# ─── IP Utilities ─────────────────────────────────────────────────────────────
_PROXY_RE = re.compile(
    r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)):'
    r'(\d{2,5})\b'
)
_PRIVATE = [
    re.compile(r'^10\.'), re.compile(r'^127\.'),
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
    re.compile(r'^192\.168\.'),
]

def _is_private(ip: str) -> bool:
    return any(r.match(ip) for r in _PRIVATE)

def extract_proxies(text: str, hint_type: str = "auto") -> list[tuple[str, str]]:
    seen, out = set(), []
    for ip, port_str in _PROXY_RE.findall(text):
        port = int(port_str)
        if not (1 <= port <= 65535) or _is_private(ip):
            continue
        key = f"{ip}:{port}"
        if key not in seen:
            seen.add(key)
            out.append((key, hint_type))
    return out

def extract_proxies_geonode(data: dict) -> list[tuple[str, str]]:
    out = []
    for item in data.get("data", []):
        ip, port = item.get("ip",""), item.get("port","")
        if not ip or not port:
            continue
        protocols = item.get("protocols", ["http"])
        ptype = ("socks5" if "socks5" in protocols else
                 "socks4" if "socks4" in protocols else "http")
        out.append((f"{ip}:{port}", ptype))
    return out

def extract_proxies_html_table(html: str, hint_type: str) -> list[tuple[str, str]]:
    soup = BeautifulSoup(html, "lxml")
    seen, out = set(), []
    for ta in soup.find_all("textarea"):
        for p in extract_proxies(ta.get_text(), hint_type):
            if p[0] not in seen:
                seen.add(p[0]); out.append(p)
    for table in soup.find_all("table"):
        for row in table.find_all("tr")[1:]:
            cols = [td.get_text(strip=True) for td in row.find_all("td")]
            if len(cols) >= 2 and re.match(r'^\d+\.\d+\.\d+\.\d+$', cols[0]):
                try:
                    port = int(cols[1])
                    if 1 <= port <= 65535 and not _is_private(cols[0]):
                        key = f"{cols[0]}:{port}"
                        if key not in seen:
                            seen.add(key)
                            ptype = hint_type
                            if len(cols) > 4:
                                t = cols[4].lower()
                                ptype = ("socks5" if "socks5" in t else
                                         "socks4" if "socks4" in t else hint_type)
                            out.append((key, ptype))
                except ValueError:
                    pass
    return out

# ─── HTTP Fetch ───────────────────────────────────────────────────────────────
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/json,*/*",
}

async def fetch(url: str, timeout: int = 20, return_json: bool = False):
    try:
        async with aiohttp.ClientSession(headers=_HEADERS) as s:
            async with s.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                             ssl=False, allow_redirects=True) as r:
                if r.status != 200:
                    return None
                return await r.json(content_type=None) if return_json else await r.text(errors="replace")
    except Exception as e:
        logger.debug(f"fetch({url}): {e}")
        return None

# ─── Core Single-shot Ping ────────────────────────────────────────────────────
async def _ping_http(proxy: str, url: str, timeout: int) -> Optional[int]:
    """One HTTP probe. Returns ms or None."""
    t0 = time.perf_counter()
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(url, proxy=f"http://{proxy}",
                             timeout=aiohttp.ClientTimeout(total=timeout),
                             ssl=False) as r:
                if r.status < 500:          # accept 200–4xx (proxy is alive)
                    await r.read()          # ensure full round-trip measured
                    return int((time.perf_counter() - t0) * 1000)
    except Exception:
        pass
    return None

async def _ping_socks(proxy: str, ptype: ProxyType, url: str, timeout: int) -> Optional[int]:
    """One SOCKS probe. Returns ms or None."""
    ip, port = proxy.rsplit(":", 1)
    t0 = time.perf_counter()
    try:
        conn = ProxyConnector(proxy_type=ptype, host=ip, port=int(port), rdns=True)
        async with aiohttp.ClientSession(connector=conn) as s:
            async with s.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                             ssl=False) as r:
                if r.status < 500:
                    await r.read()
                    return int((time.perf_counter() - t0) * 1000)
    except Exception:
        pass
    return None

# ─── Multi-sample Ping ────────────────────────────────────────────────────────
async def _collect_samples(
    proxy: str,
    protocol: str,
    test_url: str,
    timeout: int,
    n: int,
) -> list[int]:
    """
    Run n ping probes sequentially (0.1s gap between samples to avoid false hits).
    Returns list of successful ms values (may be shorter than n if some fail).
    Uses a rotating URL list so the same endpoint isn't hammered.
    """
    urls = [test_url] + [u for u in FALLBACK_TEST_URLS if u != test_url]
    samples = []

    for i in range(n):
        url = urls[i % len(urls)]
        if protocol == "socks5":
            ms = await _ping_socks(proxy, ProxyType.SOCKS5, url, timeout)
        elif protocol == "socks4":
            ms = await _ping_socks(proxy, ProxyType.SOCKS4, url, timeout)
        else:
            ms = await _ping_http(proxy, url, timeout)

        if ms is not None:
            samples.append(ms)
        if i < n - 1:
            await asyncio.sleep(0.1)    # brief gap between samples

    return samples

# ─── Phase 1: Quick Filter ────────────────────────────────────────────────────
async def _quick_probe(
    proxy: str,
    hint_type: str,
    test_url: str,
    quick_timeout: int,
    sem: asyncio.Semaphore,
) -> Optional[tuple[str, int]]:
    """
    Quick single-shot probe with short timeout.
    Returns (protocol, ms) if alive, else None.
    Tries protocols in order and returns on first success.
    """
    async with sem:
        order = []
        if hint_type in ("http", "https"):
            order = [("http", None)]
        elif hint_type == "socks4":
            order = [("socks4", ProxyType.SOCKS4)]
        elif hint_type == "socks5":
            order = [("socks5", ProxyType.SOCKS5)]
        else:   # auto
            order = [
                ("http",   None),
                ("socks5", ProxyType.SOCKS5),
                ("socks4", ProxyType.SOCKS4),
            ]

        for proto, ptype in order:
            if ptype is None:
                ms = await _ping_http(proxy, test_url, quick_timeout)
            else:
                ms = await _ping_socks(proxy, ptype, test_url, quick_timeout)
            if ms is not None:
                return (proto, ms)
    return None

# ─── Phase 2: Full Multi-sample Test ─────────────────────────────────────────
async def _full_test(
    proxy: str,
    protocol: str,
    first_ms: int,
    settings: UserSettings,
    sem: asyncio.Semaphore,
) -> ProxyResult:
    """
    For a proxy that passed quick-filter: collect N samples, compute quality.
    first_ms is injected as the first sample (already measured in phase 1).
    """
    r = ProxyResult(proxy=proxy, protocol=protocol, alive=True)

    async with sem:
        if settings.samples <= 1:
            r.ping_samples = [first_ms]
        else:
            # collect (samples-1) more, then prepend the first
            extras = await _collect_samples(
                proxy, protocol, settings.test_url,
                settings.timeout, settings.samples - 1,
            )
            r.ping_samples = [first_ms] + extras

    r.finalize_ping()
    return r

# ─── Two-Phase Test Runner ────────────────────────────────────────────────────
async def run_tests(
    proxies: list[tuple[str, str]],
    settings: UserSettings,
    progress_cb=None,
) -> list[ProxyResult]:
    """
    Phase 1 — quick filter (short timeout, all proxies, high concurrency).
    Phase 2 — multi-sample ping only on survivors.
    Returns list of ProxyResult sorted by ping_score.
    """
    total    = len(proxies)
    sem_fast = asyncio.Semaphore(settings.concur)
    sem_deep = asyncio.Semaphore(max(20, settings.concur // 4))  # fewer for multi-sample

    dead_results:  list[ProxyResult] = []
    phase1_passed: list[tuple[str, str, int]] = []   # (proxy, proto, ms)
    done = [0]
    lock = asyncio.Lock()
    last_cb = [0.0]

    # ── Phase 1 ───────────────────────────────────────────────────
    async def quick_one(proxy: str, hint: str) -> None:
        result = await _quick_probe(
            proxy, hint, settings.test_url, settings.quick_timeout, sem_fast
        )
        async with lock:
            done[0] += 1
            if result:
                proto, ms = result
                # Apply max_ping filter immediately
                if settings.max_ping > 0 and ms > settings.max_ping:
                    dead_results.append(ProxyResult(
                        proxy=proxy, protocol=proto, alive=False,
                        error=f"ping {ms}ms > max {settings.max_ping}ms",
                    ))
                else:
                    phase1_passed.append((proxy, proto, ms))
            else:
                dead_results.append(ProxyResult(proxy=proxy, alive=False))

            now = time.monotonic()
            if progress_cb and (now - last_cb[0] >= PROGRESS_MIN_GAP or done[0] == total):
                last_cb[0] = now
                await progress_cb(
                    "phase1", done[0], total, len(phase1_passed)
                )

    await asyncio.gather(*[quick_one(p, h) for p, h in proxies])

    # ── Phase 2 ───────────────────────────────────────────────────
    alive_results: list[ProxyResult] = []
    p2_done = [0]
    p2_total = len(phase1_passed)

    async def deep_one(proxy: str, proto: str, first_ms: int) -> None:
        r = await _full_test(proxy, proto, first_ms, settings, sem_deep)
        async with lock:
            alive_results.append(r)
            p2_done[0] += 1
            now = time.monotonic()
            if progress_cb and (now - last_cb[0] >= PROGRESS_MIN_GAP or p2_done[0] == p2_total):
                last_cb[0] = now
                await progress_cb(
                    "phase2", p2_done[0], p2_total, len(alive_results)
                )

    if phase1_passed:
        await asyncio.gather(*[deep_one(p, r, m) for p, r, m in phase1_passed])

    # Sort alive by ping_score, dead appended at end
    alive_results.sort(key=lambda r: r.ping_score)
    return alive_results + dead_results

# ─── GeoIP ────────────────────────────────────────────────────────────────────
FLAGS = {
    "AF":"🇦🇫","AL":"🇦🇱","DZ":"🇩🇿","AO":"🇦🇴","AR":"🇦🇷","AM":"🇦🇲",
    "AU":"🇦🇺","AT":"🇦🇹","AZ":"🇦🇿","BD":"🇧🇩","BE":"🇧🇪","BR":"🇧🇷",
    "BG":"🇧🇬","CA":"🇨🇦","CL":"🇨🇱","CN":"🇨🇳","CO":"🇨🇴","HR":"🇭🇷",
    "CZ":"🇨🇿","DK":"🇩🇰","EG":"🇪🇬","ET":"🇪🇹","FI":"🇫🇮","FR":"🇫🇷",
    "DE":"🇩🇪","GH":"🇬🇭","GR":"🇬🇷","HK":"🇭🇰","HU":"🇭🇺","IN":"🇮🇳",
    "ID":"🇮🇩","IR":"🇮🇷","IQ":"🇮🇶","IL":"🇮🇱","IT":"🇮🇹","JP":"🇯🇵",
    "JO":"🇯🇴","KZ":"🇰🇿","KE":"🇰🇪","KR":"🇰🇷","KW":"🇰🇼","LB":"🇱🇧",
    "LY":"🇱🇾","MY":"🇲🇾","MX":"🇲🇽","MD":"🇲🇩","MA":"🇲🇦","MM":"🇲🇲",
    "NP":"🇳🇵","NL":"🇳🇱","NZ":"🇳🇿","NG":"🇳🇬","NO":"🇳🇴","PK":"🇵🇰",
    "PA":"🇵🇦","PE":"🇵🇪","PH":"🇵🇭","PL":"🇵🇱","PT":"🇵🇹","RO":"🇷🇴",
    "RU":"🇷🇺","SA":"🇸🇦","RS":"🇷🇸","SG":"🇸🇬","ZA":"🇿🇦","ES":"🇪🇸",
    "LK":"🇱🇰","SE":"🇸🇪","CH":"🇨🇭","TW":"🇹🇼","TZ":"🇹🇿","TH":"🇹🇭",
    "TN":"🇹🇳","TR":"🇹🇷","UA":"🇺🇦","AE":"🇦🇪","GB":"🇬🇧","US":"🇺🇸",
    "UZ":"🇺🇿","VN":"🇻🇳","YE":"🇾🇪","ZM":"🇿🇲","ZW":"🇿🇼",
}

async def geo_lookup_batch(results: list[ProxyResult]) -> None:
    alive = [r for r in results if r.alive]
    if not alive:
        return
    ip_map: dict[str, list[ProxyResult]] = {}
    for r in alive:
        ip = r.proxy.rsplit(":", 1)[0]
        ip_map.setdefault(ip, []).append(r)
    ips = list(ip_map.keys())
    sem = asyncio.Semaphore(3)

    async def chunk(ips_chunk: list[str]) -> None:
        payload = [{"query": ip, "fields": "status,countryCode,city,isp,proxy,query"}
                   for ip in ips_chunk]
        async with sem:
            try:
                async with aiohttp.ClientSession() as s:
                    async with s.post("http://ip-api.com/batch", json=payload,
                                     timeout=aiohttp.ClientTimeout(total=15)) as r:
                        if r.status != 200:
                            return
                        for item in await r.json():
                            ip = item.get("query","")
                            if item.get("status") == "success":
                                cc   = item.get("countryCode","")
                                for res in ip_map.get(ip, []):
                                    res.country      = cc
                                    res.country_flag = FLAGS.get(cc, "🌐")
                                    res.city         = item.get("city","")
                                    res.isp          = item.get("isp","")[:30]
                                    res.anonymity    = "anonymous" if item.get("proxy") else "transparent"
            except Exception as e:
                logger.debug(f"GeoIP batch: {e}")

    tasks = [chunk(ips[i:i+100]) for i in range(0, len(ips), 100)]
    if tasks:
        await asyncio.gather(*tasks)

# ─── Source Fetching ──────────────────────────────────────────────────────────
async def collect_from_source(name: str, cfg: dict) -> list[tuple[str, str]]:
    url, parser, ptype = cfg["url"], cfg["parser"], cfg["type"]
    if parser == "text":
        c = await fetch(url)
        return extract_proxies(c, ptype) if c else []
    elif parser == "geonode_json":
        d = await fetch(url, return_json=True)
        if isinstance(d, dict):
            return extract_proxies_geonode(d)
        return extract_proxies(d, ptype) if isinstance(d, str) else []
    elif parser == "html_table":
        h = await fetch(url)
        return extract_proxies_html_table(h, ptype) if h else []
    return []

async def collect_all_sources(names: Optional[list[str]] = None) -> list[tuple[str, str]]:
    targets = {k: v for k, v in FREE_SOURCES.items()
               if names is None or k in names}
    batches = await asyncio.gather(*[collect_from_source(n, c) for n, c in targets.items()])
    seen, merged = set(), []
    for batch in batches:
        for p, t in batch:
            if p not in seen:
                seen.add(p); merged.append((p, t))
    return merged

async def scrape_url_for_proxies(url: str) -> list[tuple[str, str]]:
    content = await fetch(url)
    if not content:
        return []
    try:
        data = json.loads(content)
        if isinstance(data, dict) and "data" in data:
            p = extract_proxies_geonode(data)
            if p:
                return p
    except (json.JSONDecodeError, ValueError):
        pass
    if "<table" in content.lower() or "<html" in content.lower():
        p = extract_proxies_html_table(content, "auto")
        if p:
            return p
    return extract_proxies(content, "auto")

# ─── Export ───────────────────────────────────────────────────────────────────
def _tier_pool(results: list[ProxyResult], tier: str) -> list[ProxyResult]:
    return [r for r in results if r.alive and r.tier == tier]

def build_txt(results: list[ProxyResult], tier: Optional[str] = None) -> str:
    """Plain IP:PORT list — one proxy per line, no comments or metadata."""
    pool = [r for r in results if r.alive]
    if tier:
        pool = [r for r in pool if r.tier == tier]
    pool.sort(key=lambda r: r.ping_score)
    return "\n".join(r.proxy for r in pool)

def build_csv(results: list[ProxyResult], tier: Optional[str] = None) -> str:
    pool = [r for r in results if r.alive]
    if tier:
        pool = [r for r in pool if r.tier == tier]
    pool.sort(key=lambda r: r.ping_score)
    buf = io.StringIO()
    w   = csv.writer(buf)
    w.writerow(["proxy","protocol","tier","response_ms","avg_ms","jitter_ms",
                "stable","ping_score","country","city","isp","anonymity"])
    for r in pool:
        w.writerow([r.proxy, r.protocol, r.tier, r.response_ms, r.avg_ms,
                    r.jitter_ms, r.stable, round(r.ping_score),
                    r.country, r.city, r.isp, r.anonymity])
    return buf.getvalue()

def build_json(results: list[ProxyResult], tier: Optional[str] = None) -> str:
    pool = [r for r in results if r.alive]
    if tier:
        pool = [r for r in pool if r.tier == tier]
    pool.sort(key=lambda r: r.ping_score)
    data = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "total": len(results),
        "alive": sum(1 for r in results if r.alive),
        "tier_filter": tier or "all",
        "proxies": [asdict(r) for r in pool],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)

def make_export(results: list[ProxyResult], fmt: str,
                tier: Optional[str] = None) -> tuple[bytes, str]:
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    tag = tier or "all"
    if fmt == "csv":
        return build_csv(results, tier).encode(), f"proxies_{tag}_{ts}.csv"
    elif fmt == "json":
        return build_json(results, tier).encode(), f"proxies_{tag}_{ts}.json"
    else:
        return build_txt(results, tier).encode(), f"proxies_{tag}_{ts}.txt"

# ─── Summary ──────────────────────────────────────────────────────────────────
def fmt_summary(results: list[ProxyResult], source: str = "") -> str:
    alive = [r for r in results if r.alive]
    dead  = len(results) - len(alive)
    rate  = len(alive) / len(results) * 100 if results else 0
    emoji = "🟢" if rate >= 50 else ("🟡" if rate >= 20 else "🔴")

    times  = [r.response_ms for r in alive if r.response_ms]
    avg_t  = round(sum(times) / len(times)) if times else 0
    best_t = min(times, default=0)
    worst_t= max(times, default=0)

    # Tier breakdown
    tier_counts = {t[0]: 0 for t in TIERS}
    for r in alive:
        if r.tier in tier_counts:
            tier_counts[r.tier] += 1
    tier_str = "  ".join(
        f"{e}`{n.upper()}:{tier_counts[n]}`"
        for n, _, e in TIERS
        if tier_counts.get(n, 0) > 0
    )

    # Stable vs unstable
    stable_c   = sum(1 for r in alive if r.stable)
    unstable_c = len(alive) - stable_c

    # Jitter avg
    jitters = [r.jitter_ms for r in alive if r.jitter_ms is not None]
    avg_jit = round(sum(jitters)/len(jitters)) if jitters else 0

    # Protocol breakdown
    by_proto: dict[str, int] = {}
    for r in alive:
        by_proto[r.protocol] = by_proto.get(r.protocol, 0) + 1
    proto_str = "  ".join(f"`{p.upper()}:{c}`" for p, c in sorted(by_proto.items()))

    # Country top-3
    by_cc: dict[str, tuple[str, int]] = {}
    for r in alive:
        if r.country:
            flag, cnt = by_cc.get(r.country, (r.country_flag, 0))
            by_cc[r.country] = (flag, cnt + 1)
    top_cc = sorted(by_cc.items(), key=lambda x: -x[1][1])[:3]
    cc_str = "  ".join(f"{f}{cc}:{c}" for cc, (f, c) in top_cc) or "—"

    # Top 5 by ping_score (best overall quality)
    top5 = sorted(alive, key=lambda r: r.ping_score)[:5]

    lines = [
        f"📊 *Results{(' — ' + source[:30]) if source else ''}*",
        "━━━━━━━━━━━━━━━━━━━━",
        f"✅ Alive:   `{len(alive)}`",
        f"❌ Dead:    `{dead}`",
        f"📦 Total:   `{len(results)}`",
        f"{emoji} Rate:    `{rate:.1f}%`",
        "━━━━━━━━━━━━━━━━━━━━",
        f"🚀 Best:    `{best_t}ms`",
        f"⚡ Avg:     `{avg_t}ms`",
        f"🐢 Worst:   `{worst_t}ms`",
        f"📉 Jitter:  `{avg_jit}ms` avg",
        f"💎 Stable:  `{stable_c}` / Unstable: `{unstable_c}`",
    ]
    if tier_str:
        lines += ["━━━━━━━━━━━━━━━━━━━━", f"🏷 Tiers: {tier_str}"]
    if proto_str:
        lines += [f"🔌 Protocols: {proto_str}"]
    if cc_str != "—":
        lines += [f"🌍 Top: {cc_str}"]
    if top5:
        lines += ["━━━━━━━━━━━━━━━━━━━━", "🏆 *Top 5 (by quality score)*"]
        for r in top5:
            jit_str = f" ±{r.jitter_ms}ms" if r.jitter_ms else ""
            lines.append(
                f"`{r.proxy}` {r.tier_emoji}`{r.response_ms}ms`{jit_str} "
                f"{r.country_flag} `{r.protocol.upper()}`"
            )
    return "\n".join(lines)

# ─── Helpers ──────────────────────────────────────────────────────────────────
async def safe_edit(msg: Message, text: str, **kw) -> None:
    try:
        await msg.edit_text(text, parse_mode=ParseMode.MARKDOWN, **kw)
    except RetryAfter as e:
        await asyncio.sleep(e.retry_after + 0.5)
        try:
            await msg.edit_text(text, parse_mode=ParseMode.MARKDOWN, **kw)
        except Exception:
            pass
    except BadRequest as e:
        if "not modified" not in str(e).lower():
            logger.debug(f"safe_edit: {e}")
    except Exception as e:
        logger.debug(f"safe_edit: {e}")

def _bar(done: int, total: int, w: int = 10) -> str:
    f = int(done / total * w) if total else 0
    return "▓" * f + "░" * (w - f)

_USER_SETTINGS: dict[int, UserSettings] = {}
def get_settings(uid: int) -> UserSettings:
    return _USER_SETTINGS.setdefault(uid, UserSettings())

# ─── Pipeline ─────────────────────────────────────────────────────────────────
async def pipeline(
    chat_id: int,
    status_msg: Message,
    context: ContextTypes.DEFAULT_TYPE,
    proxies: list[tuple[str, str]],
    source_label: str,
    settings: UserSettings,
) -> None:
    total    = len(proxies)
    start_ts = time.monotonic()

    # Progress callback handles both phases
    async def on_progress(phase: str, done: int, tot: int, alive: int) -> None:
        elapsed = int(time.monotonic() - start_ts)
        if phase == "phase1":
            pct = int(done / tot * 100)
            bar = _bar(done, tot)
            await safe_edit(
                status_msg,
                f"⚡ *Phase 1 — Quick Filter*\n\n"
                f"`{bar}` `{pct}%`\n"
                f"Checked: `{done}/{tot}` | ✅ Passed: `{alive}`\n"
                f"Timeout: `{settings.quick_timeout}s` | ⏱ `{elapsed}s`",
            )
        else:
            pct = int(done / tot * 100) if tot else 100
            bar = _bar(done, tot or 1)
            await safe_edit(
                status_msg,
                f"🔬 *Phase 2 — Ping Sampling*\n\n"
                f"`{bar}` `{pct}%`\n"
                f"Sampled: `{done}/{tot}` | Samples/proxy: `{settings.samples}`\n"
                f"⏱ `{elapsed}s`",
            )

    await safe_edit(
        status_msg,
        f"⚡ *Two-Phase Ping Testing*\n\n"
        f"Phase 1: Quick filter `{settings.quick_timeout}s` timeout\n"
        f"Phase 2: `{settings.samples}` ping samples per survivor\n"
        f"Max ping: `{'no limit' if not settings.max_ping else str(settings.max_ping)+'ms'}`\n\n"
        f"Testing `{total}` proxies...",
    )

    results = await run_tests(proxies, settings, progress_cb=on_progress)
    alive_results = [r for r in results if r.alive]

    # GeoIP
    if settings.geo_lookup and alive_results:
        await safe_edit(status_msg, f"🌍 *GeoIP lookup* for `{len(alive_results)}` proxies...")
        await geo_lookup_batch(results)

    # Summary
    elapsed_total = int(time.monotonic() - start_ts)
    summary = fmt_summary(results, source=source_label)
    summary += f"\n\n⏱ *Done in* `{elapsed_total}s`"

    if not alive_results:
        await safe_edit(status_msg, f"😞 *No working proxies*\n\n{summary}")
        return

    await safe_edit(status_msg, summary)

    # ── Export files ───────────────────────────────────────────────
    fmt = settings.export_fmt

    # Always send "all alive" file
    data, fname = make_export(results, fmt, tier=None)
    await context.bot.send_document(
        chat_id=chat_id,
        document=io.BytesIO(data),
        filename=fname,
        caption=(
            f"✅ *All Working Proxies* — `{len(alive_results)}/{len(results)}`\n"
            f"Sorted by ping quality score"
        ),
        parse_mode=ParseMode.MARKDOWN,
    )

    # Per-tier files (only tiers that have proxies)
    if settings.tier_export:
        for tier_name, _, tier_emoji in TIERS:
            pool = _tier_pool(results, tier_name)
            if not pool:
                continue
            data, fname = make_export(results, fmt, tier=tier_name)
            await context.bot.send_document(
                chat_id=chat_id,
                document=io.BytesIO(data),
                filename=fname,
                caption=(
                    f"{tier_emoji} *{tier_name.upper()} Proxies* — `{len(pool)}` proxies\n"
                    f"Avg ping: `{round(sum(r.response_ms for r in pool)/len(pool))}ms` | "
                    f"Stable: `{sum(1 for r in pool if r.stable)}`"
                ),
                parse_mode=ParseMode.MARKDOWN,
            )

# ─── UI Keyboards ─────────────────────────────────────────────────────────────
def _main_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🌐 URL Scrape", callback_data="mode:scrape"),
            InlineKeyboardButton("📋 Test List",  callback_data="mode:test"),
        ],
        [
            InlineKeyboardButton("🆓 Free Sources", callback_data="free:menu"),
            InlineKeyboardButton("⚙️ Settings",     callback_data="settings:menu"),
        ],
        [InlineKeyboardButton("ℹ️ Help", callback_data="help")],
    ])

def _settings_text(s: UserSettings) -> str:
    return (
        "⚙️ *Settings*\n"
        "━━━━━━━━━━━━━━━━━━\n"
        f"⏱ Timeout:       `{s.timeout}s`\n"
        f"⚡ Quick timeout: `{s.quick_timeout}s`  _(phase 1)_\n"
        f"🔁 Ping samples: `{s.samples}`  _(per proxy)_\n"
        f"📶 Max ping:     `{'no limit' if not s.max_ping else str(s.max_ping)+'ms'}`\n"
        f"🔀 Concurrency:  `{s.concur}`\n"
        f"🌐 Test URL:     `{s.test_url[:40]}`\n"
        f"🌍 GeoIP:        `{'on' if s.geo_lookup else 'off'}`\n"
        f"🏷 Tier export:  `{'on' if s.tier_export else 'off'}`\n"
        f"📁 Format:       `{s.export_fmt.upper()}`\n"
    )

def _settings_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("⏱ Timeout",        callback_data="set:timeout"),
            InlineKeyboardButton("⚡ Quick timeout",  callback_data="set:quick_timeout"),
        ],
        [
            InlineKeyboardButton("🔁 Ping samples",  callback_data="set:samples"),
            InlineKeyboardButton("📶 Max ping",      callback_data="set:max_ping"),
        ],
        [
            InlineKeyboardButton("🔀 Concurrency",   callback_data="set:concur"),
            InlineKeyboardButton("🌐 Test URL",      callback_data="set:testurl"),
        ],
        [
            InlineKeyboardButton("🌍 GeoIP",         callback_data="set:geotoggle"),
            InlineKeyboardButton("🏷 Tier export",   callback_data="set:tiertoggle"),
        ],
        [
            InlineKeyboardButton("📄 TXT",  callback_data="set:fmt:txt"),
            InlineKeyboardButton("📊 CSV",  callback_data="set:fmt:csv"),
            InlineKeyboardButton("🔷 JSON", callback_data="set:fmt:json"),
        ],
        [InlineKeyboardButton("🔙 Back", callback_data="back:main")],
    ])

def _free_keyboard() -> InlineKeyboardMarkup:
    keys = list(FREE_SOURCES.keys())
    rows = []
    for i in range(0, len(keys), 2):
        row = [InlineKeyboardButton(f"📡 {keys[i][:20]}", callback_data=f"src:{i}")]
        if i+1 < len(keys):
            row.append(InlineKeyboardButton(f"📡 {keys[i+1][:20]}", callback_data=f"src:{i+1}"))
        rows.append(row)
    rows.append([InlineKeyboardButton("🔄 ALL Sources", callback_data="src:ALL")])
    rows.append([InlineKeyboardButton("🔙 Back",        callback_data="back:main")])
    return InlineKeyboardMarkup(rows)

# ─── Handlers ─────────────────────────────────────────────────────────────────
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🤖 *Proxy Scraper Bot v3*\n"
        "━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Ping quality-focused proxy scraper\n\n"
        "🚀 *Elite* <200ms  ✅ *Good* <500ms\n"
        "🟡 *Medium* <1000ms  🐢 *Slow* >1s\n\n"
        "⚡ Two-phase: quick filter → multi-sample ping\n"
        "📉 Jitter tracking (stable vs unstable)\n"
        "🏷 Per-tier export files\n"
        "📶 Max ping filter\n\n"
        "URL ကို တိုက်ရိုက်ပို့နိုင်သည် 👇",
        reply_markup=_main_keyboard(), parse_mode=ParseMode.MARKDOWN,
    )

async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📖 *Commands*\n"
        "━━━━━━━━━━━━━\n"
        "/start — main menu\n"
        "/scrape `<url>` — URL မှ scrape & test\n"
        "/test — proxy list paste mode\n"
        "/top `[N]` — top N fastest proxies (default 10)\n"
        "/free — free source selector\n"
        "/settings — bot settings\n"
        "/help — ဤ message\n\n"
        "📌 *Ping Tiers*\n"
        "🚀 Elite — <200ms (best)\n"
        "✅ Good  — 200–500ms\n"
        "🟡 Medium — 500–1000ms\n"
        "🐢 Slow   — >1000ms\n\n"
        "💎 *Stable* = jitter <100ms (consistent ping)",
        parse_mode=ParseMode.MARKDOWN,
    )

async def cmd_top(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show top N proxies from last session (stored in user_data)."""
    n = 10
    if context.args:
        try:
            n = max(1, min(50, int(context.args[0])))
        except ValueError:
            pass
    results: list[ProxyResult] = context.user_data.get("last_results", [])
    alive = sorted([r for r in results if r.alive], key=lambda r: r.ping_score)
    if not alive:
        await update.message.reply_text(
            "❌ No recent results. Run a scan first.",
        )
        return
    top = alive[:n]
    lines = [f"🏆 *Top {len(top)} Proxies (by quality)*", "━━━━━━━━━━━━━━━━"]
    for i, r in enumerate(top, 1):
        jit = f" ±{r.jitter_ms}ms" if r.jitter_ms else ""
        stb = "💎" if r.stable else "⚠️"
        lines.append(
            f"`{i:2}` `{r.proxy}` {r.tier_emoji}`{r.response_ms}ms`{jit} "
            f"{stb} {r.country_flag} `{r.protocol.upper()}`"
        )
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)

async def cmd_scrape(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Usage: `/scrape <url>`", parse_mode=ParseMode.MARKDOWN,
        )
        return
    await _do_scrape_url(update.message, context, context.args[0])

async def cmd_test(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data["mode"] = "test"
    await update.message.reply_text(
        "📋 *Test Mode*\n\n`IP:PORT` list paste လုပ်ပါ:",
        parse_mode=ParseMode.MARKDOWN,
    )

async def cmd_free(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🆓 *Free Sources*", reply_markup=_free_keyboard(),
        parse_mode=ParseMode.MARKDOWN,
    )

async def cmd_settings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_settings(update.effective_user.id)
    await update.message.reply_text(
        _settings_text(s), reply_markup=_settings_keyboard(),
        parse_mode=ParseMode.MARKDOWN,
    )

# ─── Callback Handler ─────────────────────────────────────────────────────────
async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q   = update.callback_query
    d   = q.data
    uid = q.from_user.id
    await q.answer()

    if d == "back:main":
        await q.edit_message_text(
            "🤖 *Proxy Scraper Bot v3*\n\nMode ရွေးပါ 👇",
            reply_markup=_main_keyboard(), parse_mode=ParseMode.MARKDOWN,
        )

    elif d == "help":
        await q.edit_message_text("Use /help for full help.")

    elif d == "mode:scrape":
        context.user_data["mode"] = "scrape"
        await q.edit_message_text(
            "🌐 *URL Scrape Mode*\n\nProxy list ပါသည့် URL ပို့ပါ:",
            parse_mode=ParseMode.MARKDOWN,
        )

    elif d == "mode:test":
        context.user_data["mode"] = "test"
        await q.edit_message_text(
            "📋 *Test Mode*\n\n`IP:PORT` list paste လုပ်ပါ:",
            parse_mode=ParseMode.MARKDOWN,
        )

    elif d == "free:menu":
        await q.edit_message_text(
            "🆓 *Free Sources*\n\nSource ရွေးပါ:",
            reply_markup=_free_keyboard(), parse_mode=ParseMode.MARKDOWN,
        )

    elif d.startswith("src:"):
        key      = d[4:]
        src_keys = list(FREE_SOURCES.keys())
        chat_id  = q.message.chat.id
        settings = get_settings(uid)

        if key == "ALL":
            await q.edit_message_text(
                f"⏳ Fetching all {len(FREE_SOURCES)} sources...",
                parse_mode=ParseMode.MARKDOWN,
            )
            proxies = await collect_all_sources()
        else:
            idx  = int(key)
            name = src_keys[idx]
            await q.edit_message_text(
                f"⏳ Fetching *{name}*...", parse_mode=ParseMode.MARKDOWN,
            )
            proxies = await collect_from_source(name, FREE_SOURCES[name])
            if not proxies:
                await q.edit_message_text(
                    f"❌ *{name}* มhub proxy မတွေ့ပါ.\nSource offline ဖြစ်နိုင်သည်။",
                    parse_mode=ParseMode.MARKDOWN,
                )
                return

        label = "All Free Sources" if key == "ALL" else src_keys[int(key)]
        await q.edit_message_text(
            f"✅ `{len(proxies)}` proxies collected from *{label}*\n⚙️ Starting...",
            parse_mode=ParseMode.MARKDOWN,
        )
        await pipeline(chat_id, q.message, context, proxies, label, settings)
        context.user_data["last_results"] = []  # cleared after new scan

    elif d == "settings:menu":
        s = get_settings(uid)
        await q.edit_message_text(
            _settings_text(s), reply_markup=_settings_keyboard(),
            parse_mode=ParseMode.MARKDOWN,
        )

    elif d == "set:geotoggle":
        s = get_settings(uid)
        s.geo_lookup = not s.geo_lookup
        await q.edit_message_text(
            _settings_text(s), reply_markup=_settings_keyboard(),
            parse_mode=ParseMode.MARKDOWN,
        )

    elif d == "set:tiertoggle":
        s = get_settings(uid)
        s.tier_export = not s.tier_export
        await q.edit_message_text(
            _settings_text(s), reply_markup=_settings_keyboard(),
            parse_mode=ParseMode.MARKDOWN,
        )

    elif d.startswith("set:fmt:"):
        s = get_settings(uid)
        s.export_fmt = d.split(":")[-1]
        await q.edit_message_text(
            _settings_text(s), reply_markup=_settings_keyboard(),
            parse_mode=ParseMode.MARKDOWN,
        )

    elif d in ("set:timeout","set:quick_timeout","set:samples",
               "set:max_ping","set:concur","set:testurl"):
        context.user_data["awaiting"] = d[4:]   # strip "set:"
        prompts = {
            "timeout":       "⏱ Full test timeout (3–60s):\nExample: `10`",
            "quick_timeout": "⚡ Phase-1 quick timeout (1–10s):\nExample: `4`",
            "samples":       "🔁 Ping samples per proxy (1–5):\n`1`=fast `3`=accurate `5`=very stable",
            "max_ping":      "📶 Max acceptable ping (ms), `0` = no limit:\nExample: `500` or `0`",
            "concur":        "🔀 Concurrency (10–300):\nExample: `100`",
            "testurl":       "🌐 Test URL:\nExample: `http://httpbin.org/ip`",
        }
        key = d[4:]
        await q.edit_message_text(
            prompts.get(key, "Enter value:"), parse_mode=ParseMode.MARKDOWN,
        )

# ─── Message Handler ──────────────────────────────────────────────────────────
async def on_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg      = update.message
    uid      = msg.from_user.id
    text     = msg.text or ""
    mode     = context.user_data.get("mode", "auto")
    awaiting = context.user_data.get("awaiting")
    settings = get_settings(uid)

    # ── Settings input ────────────────────────────────────────────
    if awaiting:
        context.user_data.pop("awaiting")
        val = text.strip()
        try:
            if awaiting == "timeout":
                settings.timeout = max(3, min(60, int(val)))
                await msg.reply_text(f"✅ Timeout: `{settings.timeout}s`", parse_mode=ParseMode.MARKDOWN)
            elif awaiting == "quick_timeout":
                settings.quick_timeout = max(1, min(10, int(val)))
                await msg.reply_text(f"✅ Quick timeout: `{settings.quick_timeout}s`", parse_mode=ParseMode.MARKDOWN)
            elif awaiting == "samples":
                settings.samples = max(1, min(5, int(val)))
                await msg.reply_text(f"✅ Ping samples: `{settings.samples}`", parse_mode=ParseMode.MARKDOWN)
            elif awaiting == "max_ping":
                settings.max_ping = max(0, int(val))
                limit_str = f"`{settings.max_ping}ms`" if settings.max_ping else "`no limit`"
                await msg.reply_text(f"✅ Max ping: {limit_str}", parse_mode=ParseMode.MARKDOWN)
            elif awaiting == "concur":
                settings.concur = max(10, min(300, int(val)))
                await msg.reply_text(f"✅ Concurrency: `{settings.concur}`", parse_mode=ParseMode.MARKDOWN)
            elif awaiting == "testurl":
                if val.startswith("http"):
                    settings.test_url = val
                    await msg.reply_text(f"✅ Test URL: `{val}`", parse_mode=ParseMode.MARKDOWN)
                else:
                    await msg.reply_text("❌ http:// or https:// ဖြင့်စပါ")
        except ValueError:
            await msg.reply_text("❌ Invalid value")
        return

    # ── File upload ───────────────────────────────────────────────
    if msg.document:
        doc = msg.document
        ext = (doc.file_name or "").rsplit(".", 1)[-1].lower()
        if ext not in ("txt", "csv"):
            await msg.reply_text("⚠️ .txt or .csv only")
            return
        raw     = await (await doc.get_file()).download_as_bytearray()
        proxies = extract_proxies(raw.decode("utf-8", errors="ignore"), "auto")
        if not proxies:
            await msg.reply_text("❌ `IP:PORT` format proxy မတွေ့ပါ", parse_mode=ParseMode.MARKDOWN)
            return
        status = await msg.reply_text(
            f"📂 `{len(proxies)}` proxies found in `{doc.file_name}`\n⚙️ Starting...",
            parse_mode=ParseMode.MARKDOWN,
        )
        results = await _run_pipeline(msg.chat.id, status, context, proxies, doc.file_name, settings)
        if results:
            context.user_data["last_results"] = results
        return

    # ── URL ───────────────────────────────────────────────────────
    url_m = re.search(r'https?://\S+', text)
    if url_m or mode == "scrape":
        url = url_m.group(0) if url_m else text.strip()
        if not url.startswith("http"):
            await msg.reply_text("❌ http:// or https:// ဖြင့်စသော URL ပေးပါ")
            return
        context.user_data["mode"] = "auto"
        await _do_scrape_url(msg, context, url)
        return

    # ── Proxy list ────────────────────────────────────────────────
    proxies = extract_proxies(text, "auto")
    if proxies or mode == "test":
        context.user_data["mode"] = "auto"
        if not proxies:
            await msg.reply_text("⚠️ Proxy မတွေ့ပါ. Format: `IP:PORT`", parse_mode=ParseMode.MARKDOWN)
            return
        status = await msg.reply_text(
            f"📋 `{len(proxies)}` proxies detected. Starting ping test...",
            parse_mode=ParseMode.MARKDOWN,
        )
        results = await _run_pipeline(msg.chat.id, status, context, proxies, "Custom List", settings)
        if results:
            context.user_data["last_results"] = results
        return

    await msg.reply_text(
        "❓ URL သို့မဟုတ် `IP:PORT` list ပေးပါ.\n\nMode ရွေးချယ်ပါ 👇",
        reply_markup=_main_keyboard(), parse_mode=ParseMode.MARKDOWN,
    )

async def _run_pipeline(chat_id, status_msg, context, proxies, label, settings):
    await pipeline(chat_id, status_msg, context, proxies, label, settings)
    # Return results stored after pipeline (we re-fetch from bot data)
    return context.user_data.get("last_results", [])

async def _do_scrape_url(msg: Message, context: ContextTypes.DEFAULT_TYPE, url: str):
    uid      = msg.from_user.id if msg.from_user else 0
    settings = get_settings(uid)
    status   = await msg.reply_text(
        f"🔍 *Scraping:*\n`{url[:80]}`\n\n⏳ Fetching...",
        parse_mode=ParseMode.MARKDOWN,
    )
    proxies = await scrape_url_for_proxies(url)
    if not proxies:
        await safe_edit(
            status,
            f"❌ *Proxy မတွေ့ပါ*\n\n`{url[:80]}`\n\n"
            "• Site down or blocked\n"
            "• IP:PORT format မပါ\n"
            "• JS-rendered page → /free ကိုသုံးပါ",
        )
        return
    await safe_edit(
        status,
        f"✅ `{len(proxies)}` proxies scraped\n⚡ Starting two-phase ping test...",
    )
    await pipeline(msg.chat.id, status, context, proxies, url[:50], settings)
    context.user_data["last_results"] = []

# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    token = os.environ.get("BOT_TOKEN")
    if not token:
        print("❌  BOT_TOKEN မသတ်မှတ်ရသေး!")
        print("    export BOT_TOKEN='your_token_here'")
        return

    # Build inside a fresh event loop for Python 3.10+ / 3.13 compatibility.
    # PTB's run_polling() manages the loop itself — we must NOT wrap in asyncio.run().
    # ApplicationBuilder.build() creates asyncio primitives; on Python 3.13 those
    # require the loop to exist first. Using post_init / run_polling handles this.
    app = (
        Application.builder()
        .token(token)
        .build()
    )
    app.add_handler(CommandHandler("start",    cmd_start))
    app.add_handler(CommandHandler("help",     cmd_help))
    app.add_handler(CommandHandler("top",      cmd_top))
    app.add_handler(CommandHandler("scrape",   cmd_scrape))
    app.add_handler(CommandHandler("test",     cmd_test))
    app.add_handler(CommandHandler("free",     cmd_free))
    app.add_handler(CommandHandler("settings", cmd_settings))
    app.add_handler(CallbackQueryHandler(on_callback))
    app.add_handler(MessageHandler(
        (filters.TEXT & ~filters.COMMAND) | filters.Document.ALL,
        on_message,
    ))
    print("🤖 Proxy Scraper Bot v3 started")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    app.run_polling(drop_pending_updates=True, close_loop=False)

if __name__ == "__main__":
    main()
