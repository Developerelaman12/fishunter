import os, sys, json, re, ssl, socket, hashlib, html
from datetime import datetime, timezone
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import unicodedata

# СТОРОННИЕ БИБЛИОТЕКИ
import requests
import whois
import dns.resolver
from bs4 import BeautifulSoup
from dotenv import load_dotenv  # ← Добавили этот импорт

# Загружаем переменные из файла .env
load_dotenv()

# ─── НАСТРОЙКИ (БЕЗОПАСНО) ─────────────────────────────────────────────────────
# Теперь мы не пишем ключи текстом, а берем их из системы
OPENROUTER_API_KEY  = os.getenv("OPENROUTER_API_KEY")
VIRUSTOTAL_API_KEY  = os.getenv("VIRUSTOTAL_API_KEY")
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")

MODEL               = "google/gemini-2.5-flash-lite"
CACHE_FILE          = "phishing_cache.json"
EXPORT_DIR          = "phishing_reports"

# Омографические символы юникода → латинские эквиваленты
HOMOGRAPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
    'у': 'y', 'і': 'i', 'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g', 'ո': 'n',
    'ȃ': 'a', 'ȯ': 'o', 'ė': 'e', 'ị': 'i', 'ọ': 'o', 'ụ': 'u',
    'ḷ': 'l', 'ṃ': 'm', 'ṅ': 'n', 'ṛ': 'r', 'ṡ': 's', 'ṭ': 't',
}

# ─── БАЗА ПОПУЛЯРНЫХ БРЕНДОВ (typosquatting) ───────────────────────────────────
KNOWN_BRANDS = [
    "google", "facebook", "apple", "microsoft", "amazon", "paypal", "netflix",
    "instagram", "twitter", "linkedin", "dropbox", "adobe", "ebay", "walmart",
    "chase", "bankofamerica", "wellsfargo", "citibank", "hsbc", "barclays",
    "americanexpress", "visa", "mastercard", "steam", "discord", "spotify",
    "youtube", "gmail", "yahoo", "outlook", "office365", "icloud",
    "sberbank", "tinkoff", "vtb", "alfabank", "raiffeisen",
]

BRAND_LOGOS = [
    "paypal", "visa", "mastercard", "apple", "google", "microsoft",
    "amazon", "ebay", "netflix", "facebook", "instagram", "twitter",
    "sberbank", "tinkoff", "vtb", "alfabank",
]

RED   = "\033[91m";  YELLOW = "\033[93m";  GREEN  = "\033[92m"
CYAN  = "\033[96m";  BOLD   = "\033[1m";   RESET  = "\033[0m"
DIM   = "\033[2m"


# ══════════════════════════════════════════════════════════════════════════════
#  КЭШ
# ══════════════════════════════════════════════════════════════════════════════

def _load_cache() -> dict:
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def _save_cache(cache: dict):
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def _cache_key(url: str) -> str:
    return hashlib.md5(url.lower().encode()).hexdigest()[:12]


# ══════════════════════════════════════════════════════════════════════════════
#  МОДУЛЬ 1 — БАЗОВАЯ ИНФОРМАЦИЯ
# ══════════════════════════════════════════════════════════════════════════════

def module_basic(url: str, domain: str) -> dict:
    info = {
        "ip": "", "status_code": None, "page_title": "",
        "redirects": [], "final_url": url,
        "has_ip_in_url": bool(re.match(r"\d{1,3}(\.\d{1,3}){3}", domain)),
        "domain_length": len(domain),
        "subdomains_count": max(0, len(domain.split(".")) - 2),
        "suspicious_keywords": [],
        "html_content": "",
        "error": None,
    }

    suspicious_words = [
        "login", "secure", "account", "update", "verify", "bank", "paypal",
        "signin", "password", "confirm", "support", "billing", "wallet",
        "credentials", "ebay", "amazon", "apple", "microsoft", "google",
    ]
    info["suspicious_keywords"] = [w for w in suspicious_words if w in url.lower()]

    try:
        info["ip"] = socket.gethostbyname(domain)
    except Exception:
        info["ip"] = "н/д"

    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                  "AppleWebKit/537.36 Chrome/120.0"}
        r = requests.get(
            url if url.startswith("http") else "http://" + url,
            headers=headers, timeout=10, allow_redirects=True
        )
        info["status_code"]  = r.status_code
        info["final_url"]    = r.url
        info["redirects"]    = [rr.url for rr in r.history]
        info["html_content"] = r.text[:80_000]
        title = re.search(r"<title>(.*?)</title>", r.text, re.I | re.S)
        info["page_title"] = title.group(1).strip()[:200] if title else ""
    except Exception as e:
        info["error"] = str(e)

    return info


# ══════════════════════════════════════════════════════════════════════════════
#  МОДУЛЬ 2 — SSL
# ══════════════════════════════════════════════════════════════════════════════

def module_ssl(domain: str) -> dict:
    result = {"has_ssl": False, "ssl_issuer": "", "ssl_subject": "",
              "ssl_expires": "", "ssl_days_left": None}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(6)
            s.connect((domain, 443))
            cert = s.getpeercert()
        result["has_ssl"] = True
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        result["ssl_issuer"]  = issuer.get("organizationName", "")
        result["ssl_subject"] = subject.get("commonName", "")
        exp = cert.get("notAfter", "")
        if exp:
            result["ssl_expires"] = exp
            try:
                exp_dt = datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                result["ssl_days_left"] = (exp_dt - datetime.now(timezone.utc)).days
            except Exception:
                pass
    except Exception:
        pass
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  МОДУЛЬ 3 — WHOIS (возраст домена)
# ══════════════════════════════════════════════════════════════════════════════

def module_whois(domain: str) -> dict:
    result = {"domain_age_days": None, "registrar": "", "country": "",
              "creation_date": "", "expiration_date": "", "whois_error": None}
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            result["domain_age_days"] = (datetime.now(timezone.utc) - creation).days
            result["creation_date"]   = creation.strftime("%Y-%m-%d")

        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]
        if expiration:
            result["expiration_date"] = str(expiration)[:10]

        result["registrar"] = str(w.registrar or "")[:80]
        result["country"]   = str(w.country  or "")[:10]
    except Exception as e:
        result["whois_error"] = str(e)
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  МОДУЛЬ 4 — DNS
# ══════════════════════════════════════════════════════════════════════════════

def module_dns(domain: str) -> dict:
    result = {"has_mx": False, "has_spf": False, "has_dmarc": False,
              "mx_records": [], "spf_record": "", "dmarc_record": "",
              "a_ttl": None, "dns_error": None}
    try:
        answers = dns.resolver.resolve(domain, "A")
        result["a_ttl"] = answers.rrset.ttl
    except Exception:
        pass
    try:
        mx = dns.resolver.resolve(domain, "MX")
        result["has_mx"]     = True
        result["mx_records"] = [str(r.exchange)[:50] for r in mx][:3]
    except Exception:
        pass
    try:
        txt = dns.resolver.resolve(domain, "TXT")
        for record in txt:
            s = str(record)
            if "v=spf1" in s.lower():
                result["has_spf"]    = True
                result["spf_record"] = s[:120]
    except Exception:
        pass
    try:
        dmarc = dns.resolver.resolve("_dmarc." + domain, "TXT")
        for record in dmarc:
            s = str(record)
            if "v=dmarc1" in s.lower():
                result["has_dmarc"]    = True
                result["dmarc_record"] = s[:120]
    except Exception:
        pass
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  МОДУЛЬ 5 — HTML-АНАЛИЗ (+ анализ action форм)
# ══════════════════════════════════════════════════════════════════════════════

def module_html(html_content: str, domain: str, base_url: str = "") -> dict:
    result = {
        "password_forms": 0, "hidden_iframes": 0,
        "external_links": 0, "internal_links": 0,
        "external_scripts": 0, "brand_logos_found": [],
        "has_login_form": False, "obfuscated_js": False,
        "meta_refresh": False,
        # ── новые поля анализа форм ──
        "forms_analysis":     [],
        "forms_total":        0,
        "forms_external":     0,
        "forms_ip_action":    0,
        "forms_empty_action": 0,
        "forms_http_mixed":   0,
        "forms_danger_count": 0,
        # ── новые поля v3 ──
        "brand_in_title":       False,
        "brand_title_mismatch": False,
        "favicon_external":     False,
        "favicon_url":          "",
        "js_obfuscation_score": 0,   # 0-100
        "clipboard_hijack":     False,
        "fake_captcha":         False,
        "data_uri_count":       0,
    }
    if not html_content:
        return result

    try:
        soup = BeautifulSoup(html_content, "lxml")

        # ── Формы с паролем (старая логика) ──
        for inp in soup.find_all("input", {"type": "password"}):
            result["password_forms"] += 1
        result["has_login_form"] = result["password_forms"] > 0

        # ── Скрытые iframe ──
        for iframe in soup.find_all("iframe"):
            style = iframe.get("style", "")
            w = iframe.get("width", "")
            h = iframe.get("height", "")
            if ("display:none" in style.replace(" ", "") or
                    w in ("0", "1") or h in ("0", "1")):
                result["hidden_iframes"] += 1

        # ── Внешние / внутренние ссылки ──
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("http") and domain not in href:
                result["external_links"] += 1
            elif not href.startswith("http") or domain in href:
                result["internal_links"] += 1

        # ── Внешние скрипты ──
        for s in soup.find_all("script", src=True):
            if domain not in s["src"] and s["src"].startswith("http"):
                result["external_scripts"] += 1

        # ── Логотипы брендов ──
        page_lower = html_content.lower()
        for brand in BRAND_LOGOS:
            if brand in page_lower:
                result["brand_logos_found"].append(brand)

        # ── Meta refresh ──
        for meta in soup.find_all("meta"):
            if "refresh" in str(meta.get("http-equiv", "")).lower():
                result["meta_refresh"] = True

        # ═══════════════════════════════════════════════════════════
        #  УЛУЧШЕННАЯ ДЕТЕКЦИЯ ОБФУСКАЦИИ JS (v3)
        # ═══════════════════════════════════════════════════════════
        js_text = " ".join(s.get_text() for s in soup.find_all("script") if not s.get("src"))
        obf_score = 0
        obf_signals = [
            (r"\beval\s*\(", 30),
            (r"\batob\s*\(",  25),                     # base64 decode
            (r"String\.fromCharCode\s*\(", 25),        # char-by-char строки
            (r"\bunescape\s*\(", 20),
            (r"\\x[0-9a-fA-F]{2}", 15),                # hex-escaped строки
            (r"\\u[0-9a-fA-F]{4}", 10),                # unicode-escaped
            (r"\.replace\s*\(/[^/]{20,}/", 15),        # regex-замена длинная
            (r"\bwindow\['[a-z]+'\]\s*=", 10),          # обращение к window через строку
            (r"document\['write'\]",        20),
        ]
        for pattern, weight in obf_signals:
            if re.search(pattern, js_text):
                obf_score += weight
        result["js_obfuscation_score"] = min(obf_score, 100)
        result["obfuscated_js"] = obf_score >= 30

        # ── Clipboard hijack ──
        if "clipboard" in js_text.lower() and ("writeText" in js_text or "setData" in js_text):
            result["clipboard_hijack"] = True

        # ── Fake captcha (популярная техника 2024–2025) ──
        captcha_keywords = ["verify you are human", "i am not a robot",
                            "press and hold", "click and hold", "докажи что ты человек"]
        for kw in captcha_keywords:
            if kw in page_lower:
                result["fake_captcha"] = True
                break

        # ── Data URI (встраивание ресурсов, уклонение от сканеров) ──
        result["data_uri_count"] = page_lower.count("data:image")

        # ═══════════════════════════════════════════════════════════
        #  БРЕНД В TITLE vs ДОМЕН
        # ═══════════════════════════════════════════════════════════
        title_tag = soup.find("title")
        title_text = (title_tag.get_text() if title_tag else "").lower()
        for brand in KNOWN_BRANDS:
            if brand in title_text:
                result["brand_in_title"] = True
                # Если бренд в заголовке, но не в домене — подозрительно
                if brand not in domain.lower():
                    result["brand_title_mismatch"] = True
                break

        # ═══════════════════════════════════════════════════════════
        #  FAVICON — внешний источник
        # ═══════════════════════════════════════════════════════════
        for link in soup.find_all("link", rel=True):
            rel = " ".join(link.get("rel", [])).lower()
            if "icon" in rel:
                href = link.get("href", "")
                result["favicon_url"] = href[:100]
                if href.startswith("http") and domain not in href:
                    result["favicon_external"] = True
                break

        # ══════════════════════════════════════════════════════════════
        #  АНАЛИЗ АТРИБУТА action У ФОРМ
        # ══════════════════════════════════════════════════════════════
        forms_data = []
        for form in soup.find_all("form"):
            action       = (form.get("action") or "").strip()
            method       = (form.get("method") or "get").upper()
            has_password = bool(form.find("input", {"type": "password"}))
            has_hidden   = bool(form.find("input", {"type": "hidden"}))
            inputs_count = len(form.find_all("input"))

            form_info = {
                "action":        action,
                "method":        method,
                "has_password":  has_password,
                "has_hidden":    has_hidden,
                "inputs_count":  inputs_count,
                "action_domain": "",
                "flags":         [],
                "risk":          "safe",
            }

            if not action or action == "#":
                form_info["flags"].append("empty_action")
                form_info["risk"] = "warn"
            else:
                if action.startswith("http"):
                    action_full = action
                else:
                    action_full = f"https://{domain}/{action.lstrip('/')}"

                try:
                    parsed_action = urlparse(action_full)
                    action_domain = parsed_action.netloc
                    form_info["action_domain"] = action_domain

                    if (action_domain
                            and action_domain != domain
                            and not action_domain.endswith("." + domain)):
                        form_info["flags"].append("external_action")
                        form_info["risk"] = "danger"

                    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", action_domain):
                        form_info["flags"].append("ip_in_action")
                        form_info["risk"] = "danger"

                    page_is_https = base_url.startswith("https") if base_url else False
                    if parsed_action.scheme == "http" and page_is_https:
                        form_info["flags"].append("http_mixed_action")
                        if form_info["risk"] != "danger":
                            form_info["risk"] = "warn"

                except Exception:
                    form_info["flags"].append("unparseable_action")
                    if form_info["risk"] != "danger":
                        form_info["risk"] = "warn"

            forms_data.append(form_info)

        result["forms_analysis"]     = forms_data
        result["forms_total"]        = len(forms_data)
        result["forms_external"]     = sum(1 for f in forms_data if "external_action"   in f["flags"])
        result["forms_ip_action"]    = sum(1 for f in forms_data if "ip_in_action"      in f["flags"])
        result["forms_empty_action"] = sum(1 for f in forms_data if "empty_action"      in f["flags"])
        result["forms_http_mixed"]   = sum(1 for f in forms_data if "http_mixed_action" in f["flags"])
        result["forms_danger_count"] = sum(1 for f in forms_data if f["risk"] == "danger")

    except Exception:
        pass

    return result
    if not html_content:
        return result

    try:
        soup = BeautifulSoup(html_content, "lxml")

        # ── Формы с паролем (старая логика) ──
        for inp in soup.find_all("input", {"type": "password"}):
            result["password_forms"] += 1
        result["has_login_form"] = result["password_forms"] > 0

        # ── Скрытые iframe ──
        for iframe in soup.find_all("iframe"):
            style = iframe.get("style", "")
            w = iframe.get("width", "")
            h = iframe.get("height", "")
            if ("display:none" in style.replace(" ", "") or
                    w in ("0", "1") or h in ("0", "1")):
                result["hidden_iframes"] += 1

        # ── Внешние / внутренние ссылки ──
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("http") and domain not in href:
                result["external_links"] += 1
            elif not href.startswith("http") or domain in href:
                result["internal_links"] += 1

        # ── Внешние скрипты ──
        for s in soup.find_all("script", src=True):
            if domain not in s["src"] and s["src"].startswith("http"):
                result["external_scripts"] += 1

        # ── Логотипы брендов ──
        page_lower = html_content.lower()
        for brand in BRAND_LOGOS:
            if brand in page_lower:
                result["brand_logos_found"].append(brand)

        # ── Meta refresh ──
        for meta in soup.find_all("meta"):
            if "refresh" in str(meta.get("http-equiv", "")).lower():
                result["meta_refresh"] = True

        # ── Обфускация JS ──
        js_text = " ".join(s.get_text() for s in soup.find_all("script") if not s.get("src"))
        if "eval(" in js_text and len(js_text) > 5000:
            result["obfuscated_js"] = True

        # ══════════════════════════════════════════════════════════════
        #  НОВЫЙ БЛОК — АНАЛИЗ АТРИБУТА action У ФОРМ
        # ══════════════════════════════════════════════════════════════
        forms_data = []
        for form in soup.find_all("form"):
            action       = (form.get("action") or "").strip()
            method       = (form.get("method") or "get").upper()
            has_password = bool(form.find("input", {"type": "password"}))
            has_hidden   = bool(form.find("input", {"type": "hidden"}))
            inputs_count = len(form.find_all("input"))

            form_info = {
                "action":        action,
                "method":        method,
                "has_password":  has_password,
                "has_hidden":    has_hidden,
                "inputs_count":  inputs_count,
                "action_domain": "",
                "flags":         [],
                "risk":          "safe",   # safe | warn | danger
            }

            # Пустой или якорный action — данные могут перехватываться JS
            if not action or action == "#":
                form_info["flags"].append("empty_action")
                form_info["risk"] = "warn"

            else:
                # Нормализуем относительные URL
                if action.startswith("http"):
                    action_full = action
                else:
                    action_full = f"https://{domain}/{action.lstrip('/')}"

                try:
                    parsed_action = urlparse(action_full)
                    action_domain = parsed_action.netloc

                    form_info["action_domain"] = action_domain

                    # Домен action отличается от домена сайта
                    if (action_domain
                            and action_domain != domain
                            and not action_domain.endswith("." + domain)):
                        form_info["flags"].append("external_action")
                        form_info["risk"] = "danger"

                    # IP-адрес в action
                    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", action_domain):
                        form_info["flags"].append("ip_in_action")
                        form_info["risk"] = "danger"

                    # HTTP action на HTTPS-странице (mixed content)
                    page_is_https = base_url.startswith("https") if base_url else False
                    if parsed_action.scheme == "http" and page_is_https:
                        form_info["flags"].append("http_mixed_action")
                        if form_info["risk"] != "danger":
                            form_info["risk"] = "warn"

                except Exception:
                    form_info["flags"].append("unparseable_action")
                    if form_info["risk"] != "danger":
                        form_info["risk"] = "warn"

            forms_data.append(form_info)

        # Сохраняем результаты анализа форм
        result["forms_analysis"]     = forms_data
        result["forms_total"]        = len(forms_data)
        result["forms_external"]     = sum(1 for f in forms_data if "external_action"   in f["flags"])
        result["forms_ip_action"]    = sum(1 for f in forms_data if "ip_in_action"      in f["flags"])
        result["forms_empty_action"] = sum(1 for f in forms_data if "empty_action"      in f["flags"])
        result["forms_http_mixed"]   = sum(1 for f in forms_data if "http_mixed_action" in f["flags"])
        result["forms_danger_count"] = sum(1 for f in forms_data if f["risk"] == "danger")

    except Exception:
        pass

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  МОДУЛЬ 6 — TYPOSQUATTING
# ══════════════════════════════════════════════════════════════════════════════

def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                            prev[j] + (0 if ca == cb else 1)))
        prev = curr
    return prev[-1]

def module_typosquatting(domain: str) -> dict:
    parts = domain.split(".")
    core  = parts[-2] if len(parts) >= 2 else domain
    result = {"closest_brand": "", "edit_distance": 99,
              "is_typosquat": False, "impersonated_brand": ""}
    for brand in KNOWN_BRANDS:
        dist = _levenshtein(core.lower(), brand.lower())
        if dist < result["edit_distance"]:
            result["edit_distance"]  = dist
            result["closest_brand"]  = brand
    if (result["edit_distance"] <= 2 and
            len(result["closest_brand"]) >= 5 and
            core.lower() != result["closest_brand"].lower()):
        result["is_typosquat"]       = True
        result["impersonated_brand"] = result["closest_brand"]
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  МОДУЛЬ 7 — VIRUSTOTAL
# ══════════════════════════════════════════════════════════════════════════════

def module_virustotal(url: str) -> dict:
    result = {"vt_enabled": False, "vt_malicious": 0,
              "vt_suspicious": 0, "vt_harmless": 0,
              "vt_total": 0, "vt_error": None}
    if not VIRUSTOTAL_API_KEY:
        result["vt_error"] = "API ключ не задан (VIRUSTOTAL_API_KEY)"
        return result
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=12
        )
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            result.update({
                "vt_enabled":    True,
                "vt_malicious":  stats.get("malicious", 0),
                "vt_suspicious": stats.get("suspicious", 0),
                "vt_harmless":   stats.get("harmless", 0),
                "vt_total":      sum(stats.values()),
            })
        elif r.status_code == 404:
            r2 = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers, data={"url": url}, timeout=12
            )
            result["vt_error"] = "URL отправлен на анализ, повтори через 1 мин."
        else:
            result["vt_error"] = f"VT статус {r.status_code}"
    except Exception as e:
        result["vt_error"] = str(e)
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  МОДУЛЬ 8 — ГОМОГРАФИЧЕСКИЕ АТАКИ (Unicode/IDN спуфинг)
# ══════════════════════════════════════════════════════════════════════════════

def module_homograph(domain: str) -> dict:
    result = {
        "is_idn":             False,
        "punycode":           "",
        "ascii_equivalent":   "",
        "has_homograph":      False,
        "mixed_scripts":      False,
        "confusable_brand":   "",
        "homograph_risk":     "safe",   # safe | warn | danger
    }

    # Проверяем IDN (internationalized domain name)
    try:
        encoded = domain.encode("idna").decode("ascii")
        if encoded != domain and encoded.startswith("xn--"):
            result["is_idn"]   = True
            result["punycode"] = encoded
    except Exception:
        pass

    # Нормализуем домен через NFKD + замена омографов
    normalized = ""
    for ch in domain.lower():
        normalized += HOMOGRAPH_MAP.get(ch, ch)
    result["ascii_equivalent"] = normalized

    # Если нормализованный домен отличается — есть омографы
    if normalized != domain.lower():
        result["has_homograph"] = True

    # Проверка смешанных скриптов (кириллица + латиница в одном слове)
    has_latin = any('a' <= c <= 'z' for c in domain.lower())
    has_cyrillic = any('\u0400' <= c <= '\u04FF' for c in domain)
    if has_latin and has_cyrillic:
        result["mixed_scripts"] = True

    # Если нашли омографы/IDN — проверяем похожесть на бренд
    check_domain = normalized.split(".")[0] if "." in normalized else normalized
    if result["has_homograph"] or result["is_idn"] or result["mixed_scripts"]:
        result["homograph_risk"] = "warn"
        for brand in KNOWN_BRANDS:
            dist = _levenshtein(check_domain.lower(), brand.lower())
            if dist <= 2 and len(brand) >= 5:
                result["confusable_brand"] = brand
                result["homograph_risk"]   = "danger"
                break

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  МОДУЛЬ 9 — GOOGLE SAFE BROWSING
# ══════════════════════════════════════════════════════════════════════════════

def module_safe_browsing(url: str) -> dict:
    result = {"gsb_enabled": False, "gsb_threats": [], "gsb_error": None}
    if not GOOGLE_SAFE_BROWSING_KEY:
        result["gsb_error"] = "API ключ не задан (GOOGLE_SAFE_BROWSING_KEY)"
        return result
    try:
        body = {
            "client":    {"clientId": "phishing-checker", "clientVersion": "3.0"},
            "threatInfo": {
                "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING",
                                     "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": url}],
            }
        }
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}",
            json=body, timeout=10
        )
        if r.status_code == 200:
            result["gsb_enabled"] = True
            matches = r.json().get("matches", [])
            result["gsb_threats"] = [m.get("threatType", "") for m in matches]
    except Exception as e:
        result["gsb_error"] = str(e)
    return result

def collect_all(url: str) -> dict:
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    domain = parsed.netloc or parsed.path.split("/")[0]

    basic        = module_basic(url, domain)
    html_content = basic.pop("html_content", "")

    tasks = {
        "ssl":          lambda: module_ssl(domain),
        "whois":        lambda: module_whois(domain),
        "dns":          lambda: module_dns(domain),
        "html":         lambda: module_html(html_content, domain, base_url=url),
        "typo":         lambda: module_typosquatting(domain),
        "virustotal":   lambda: module_virustotal(url),
        "homograph":    lambda: module_homograph(domain),      # НОВЫЙ
        "safe_browsing":lambda: module_safe_browsing(url),     # НОВЫЙ
    }

    results = {"url": url, "domain": domain, "basic": basic}
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as e:
                results[name] = {"error": str(e)}

    return results


# ══════════════════════════════════════════════════════════════════════════════
#  AI — АНАЛИЗ ЧЕРЕЗ OPENROUTER
# ══════════════════════════════════════════════════════════════════════════════

def ask_ai(data: dict) -> dict:
    b   = data.get("basic",        {})
    s   = data.get("ssl",          {})
    w   = data.get("whois",        {})
    d   = data.get("dns",          {})
    h   = data.get("html",         {})
    t   = data.get("typo",         {})
    vt  = data.get("virustotal",   {})
    hg  = data.get("homograph",    {})
    gsb = data.get("safe_browsing",{})

    # ── VirusTotal блок ──
    vt_block = ""
    if vt.get("vt_enabled"):
        vt_block = f"""
🦠 VirusTotal ({vt['vt_total']} движков):
  - Вредоносных:   {vt['vt_malicious']}
  - Подозрительных:{vt['vt_suspicious']}
  - Безвредных:    {vt['vt_harmless']}"""
    elif vt.get("vt_error"):
        vt_block = f"\n🦠 VirusTotal: {vt['vt_error']}"

    # ── Google Safe Browsing блок ──
    gsb_block = ""
    if gsb.get("gsb_enabled"):
        if gsb.get("gsb_threats"):
            gsb_block = f"\n🔴 Google Safe Browsing: УГРОЗЫ НАЙДЕНЫ: {', '.join(gsb['gsb_threats'])}"
        else:
            gsb_block = "\n✅ Google Safe Browsing: угроз не обнаружено"
    elif gsb.get("gsb_error"):
        gsb_block = f"\n🔵 Google Safe Browsing: {gsb['gsb_error']}"

    whois_age = (f"{w['domain_age_days']} дней"
                 if w.get("domain_age_days") is not None else "неизвестно")

    # ── Блок анализа форм ──
    forms_lines = []
    for i, form in enumerate(h.get("forms_analysis", [])[:5], 1):
        pwd_mark  = "🔑 пароль" if form.get("has_password") else ""
        risk_icon = {"danger": "🚨", "warn": "⚠️", "safe": "✅"}.get(form.get("risk", "safe"), "")
        flags_str = ", ".join(form.get("flags", [])) or "ок"
        action_display = (form.get("action") or "(пусто)")[:70]
        forms_lines.append(
            f"  {i}. {risk_icon} action='{action_display}' "
            f"[{form.get('method','?')}] {pwd_mark} | флаги: {flags_str}"
        )
    forms_block = "\n".join(forms_lines) if forms_lines else "  Форм не обнаружено"

    # ── Новый блок: гомограф ──
    hg_block = ""
    if hg.get("has_homograph") or hg.get("is_idn") or hg.get("mixed_scripts"):
        hg_block = f"""
🔤 ГОМОГРАФИЧЕСКАЯ АТАКА (КРИТИЧНО):
  IDN домен: {'ДА (' + hg.get('punycode','') + ')' if hg.get('is_idn') else 'нет'}
  Омографические символы: {'ДА 🚨' if hg.get('has_homograph') else 'нет'}
  ASCII-эквивалент: {hg.get('ascii_equivalent','')}
  Смешанные скрипты (кирилл+латин): {'ДА 🚨' if hg.get('mixed_scripts') else 'нет'}
  Похожий бренд через омограф: {hg.get('confusable_brand','нет') or 'нет'}
  Риск: {hg.get('homograph_risk','?')}"""
    else:
        hg_block = "\n🔤 Гомографические атаки: не обнаружены"

    # ── Новый блок: расширенный HTML ──
    html_extra = f"""
  JS обфускация (0-100): {h.get('js_obfuscation_score', 0)} {'🚨 ВЫСОКАЯ' if h.get('js_obfuscation_score',0) >= 50 else ('⚠️ средняя' if h.get('js_obfuscation_score',0) >= 25 else '✅ низкая')}
  Бренд в заголовке: {'ДА' if h.get('brand_in_title') else 'нет'}
  Несоответствие бренд/домен: {'ДА 🚨' if h.get('brand_title_mismatch') else 'нет'}
  Внешний favicon: {'ДА ⚠️ (' + h.get('favicon_url','') + ')' if h.get('favicon_external') else 'нет'}
  Перехват буфера обмена: {'ДА 🚨' if h.get('clipboard_hijack') else 'нет'}
  Поддельная CAPTCHA: {'ДА 🚨' if h.get('fake_captcha') else 'нет'}
  Data URI изображений: {h.get('data_uri_count', 0)}"""

    prompt = f"""Ты — ведущий эксперт по кибербезопасности и фишингу. Проанализируй ВСЕ данные и вынеси точный вердикт.

ВАЖНО: Обращай особое внимание на несоответствия — например, если страница выглядит как PayPal, но домен не paypal.com, это почти наверняка фишинг.

🌐 ОСНОВНАЯ ИНФОРМАЦИЯ:
  URL: {data['url']}
  Домен: {data['domain']}
  IP-адрес: {b.get('ip', 'н/д')}
  HTTP статус: {b.get('status_code')}
  Заголовок страницы: {b.get('page_title', 'н/д')}
  Редиректы: {b.get('redirects') or 'нет'}
  Финальный URL: {b.get('final_url', '')}
  IP вместо домена: {'ДА ⚠️' if b.get('has_ip_in_url') else 'нет'}
  Длина домена: {b.get('domain_length')} символов
  Поддоменов: {b.get('subdomains_count')}
  Подозрительные слова в URL: {', '.join(b.get('suspicious_keywords', [])) or 'нет'}

🔒 SSL-СЕРТИФИКАТ:
  Наличие: {'✅ Есть' if s.get('has_ssl') else '❌ Отсутствует'}
  Издатель: {s.get('ssl_issuer', 'н/д')}
  Домен сертификата: {s.get('ssl_subject', 'н/д')}
  Дней до истечения: {s.get('ssl_days_left', 'н/д')}

📋 WHOIS (регистрация):
  Возраст домена: {whois_age}
  Дата регистрации: {w.get('creation_date', 'н/д')}
  Регистратор: {w.get('registrar', 'н/д')}
  Страна регистрации: {w.get('country', 'н/д')}

🔎 DNS:
  MX-записи (почта): {'✅ есть' if d.get('has_mx') else '❌ нет'}
  SPF-запись: {'✅ есть' if d.get('has_spf') else '❌ нет'}
  DMARC-запись: {'✅ есть' if d.get('has_dmarc') else '❌ нет'}
  TTL записи A: {d.get('a_ttl', 'н/д')} сек

📄 HTML-АНАЛИЗ:
  Форм с паролем: {h.get('password_forms', 0)}
  Скрытых iframe: {h.get('hidden_iframes', 0)}
  Внешних ссылок: {h.get('external_links', 0)}
  Внутренних ссылок: {h.get('internal_links', 0)}
  Внешних скриптов: {h.get('external_scripts', 0)}
  Логотипы брендов на странице: {', '.join(h.get('brand_logos_found', [])) or 'нет'}
  Meta-refresh редирект: {'ДА ⚠️' if h.get('meta_refresh') else 'нет'}
  Обфускация JS: {'ДА ⚠️' if h.get('obfuscated_js') else 'нет'}
{html_extra}

📋 АНАЛИЗ ФОРМ (атрибут action) — КЛЮЧЕВОЙ ПРИЗНАК ФИШИНГА:
  Форм всего:                {h.get('forms_total', 0)}
  Форм с внешним action:     {h.get('forms_external', 0)}  ← главный признак фишинга
  Форм с IP-адресом в action:{h.get('forms_ip_action', 0)}
  Форм с пустым action:      {h.get('forms_empty_action', 0)}
  Форм HTTP на HTTPS:        {h.get('forms_http_mixed', 0)}
  Итого опасных форм:        {h.get('forms_danger_count', 0)}
Детали каждой формы:
{forms_block}

🔤 TYPOSQUATTING:
  Похожий бренд: {t.get('closest_brand', 'н/д')}
  Расстояние Левенштейна: {t.get('edit_distance', 'н/д')}
  Вывод: {'⚠️ ВОЗМОЖЕН TYPOSQUATTING — имитирует ' + t.get('impersonated_brand','') if t.get('is_typosquat') else 'не обнаружен'}
{hg_block}
{vt_block}
{gsb_block}

Учти эти критические признаки фишинга (должны давать высокий risk_score):
- Google Safe Browsing нашёл угрозы = ФИШИНГ (95%+)
- Гомографическая атака + похожий бренд = ФИШИНГ (95%+)
- Заголовок страницы содержит бренд, которого нет в домене = ФИШИНГ (90%+)
- Поддельная CAPTCHA ("нажмите и держите") = ФИШИНГ (85%+)
- Перехват буфера обмена (clipboard hijack) = ФИШИНГ (85%+)
- Новый домен (< 30 дней) + форма с паролем + логотипы чужих брендов = ФИШИНГ (95%+)
- Форма с паролем, где action ведёт на другой домен = ФИШИНГ (95%+)
- IP-адрес в action = ФИШИНГ (98%+)
- JS обфускация > 50 + форма с паролем = ФИШИНГ (85%+)

Ответь СТРОГО в формате JSON (без markdown, без пояснений вне JSON):
{{
  "verdict": "ФИШИНГ" | "ПОДОЗРИТЕЛЬНО" | "БЕЗОПАСНО",
  "risk_score": <0–100>,
  "confidence": <0–100>,
  "red_flags": ["..."],
  "green_flags": ["..."],
  "explanation": "2–3 предложения на русском",
  "recommendation": "что делать пользователю"
}}"""

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type":  "application/json",
        "HTTP-Referer":  "https://phishing-checker.local",
        "X-Title":       "Phishing Checker v3",
    }
    body = {
        "model":       MODEL,
        "messages":    [{"role": "user", "content": prompt}],
        "temperature": 0.1,
    }
    try:
        r = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers, json=body, timeout=40
        )
        r.raise_for_status()
        content = r.json()["choices"][0]["message"]["content"].strip()
        content = re.sub(r"```json|```", "", content).strip()
        return json.loads(content)
    except requests.exceptions.HTTPError as e:
        return {"error": f"Ошибка API: {e}", "verdict": "ОШИБКА"}
    except json.JSONDecodeError:
        return {"error": "Не удалось разобрать ответ AI", "verdict": "ОШИБКА"}
    except Exception as e:
        return {"error": str(e), "verdict": "ОШИБКА"}


# ══════════════════════════════════════════════════════════════════════════════
#  ВЫВОД В ТЕРМИНАЛ
# ══════════════════════════════════════════════════════════════════════════════

def print_result(data: dict, ai: dict):
    b   = data.get("basic",         {})
    s   = data.get("ssl",           {})
    w   = data.get("whois",         {})
    d   = data.get("dns",           {})
    h   = data.get("html",          {})
    t   = data.get("typo",          {})
    vt  = data.get("virustotal",    {})
    hg  = data.get("homograph",     {})
    gsb = data.get("safe_browsing", {})

    verdict = ai.get("verdict", "ОШИБКА")
    risk    = ai.get("risk_score", "?")
    conf    = ai.get("confidence", "?")
    color   = {
        "ФИШИНГ":        RED  + BOLD,
        "ПОДОЗРИТЕЛЬНО": YELLOW + BOLD,
        "БЕЗОПАСНО":     GREEN + BOLD,
    }.get(verdict, BOLD)
    icon = {"ФИШИНГ": "🚨", "ПОДОЗРИТЕЛЬНО": "⚠️ ", "БЕЗОПАСНО": "✅"}.get(verdict, "❓")

    W = 62
    print(f"\n{'═'*W}")
    print(f"  {CYAN}{BOLD}🛡  PHISHING DETECTOR v3.0{RESET}")
    print(f"{'═'*W}")
    print(f"  🌐 URL         : {data['url']}")
    print(f"  📡 IP          : {b.get('ip','н/д')}")
    print(f"  📄 Статус      : {b.get('status_code','н/д')}")
    print(f"  🔒 SSL         : {'✅ ' + s.get('ssl_issuer','') if s.get('has_ssl') else '❌ Нет'}")
    ssl_days = s.get("ssl_days_left")
    if ssl_days is not None:
        print(f"  📅 SSL дней    : {ssl_days}")
    age = w.get("domain_age_days")
    print(f"  🗓  Возраст     : {str(age) + ' дней' if age is not None else 'неизвестно'}")
    print(f"  🏢 Регистратор : {w.get('registrar','н/д')[:45]}")
    print(f"  📬 MX / SPF    : {'✅' if d.get('has_mx') else '❌'} / {'✅' if d.get('has_spf') else '❌'}")
    print(f"  🔑 Форм pwd    : {h.get('password_forms',0)}   | iframe скрытых: {h.get('hidden_iframes',0)}")

    # ── Гомографические атаки ──
    if hg.get("has_homograph") or hg.get("is_idn") or hg.get("mixed_scripts"):
        print(f"  {'─'*58}")
        print(f"  {RED}🔤 ГОМОГРАФИЧЕСКАЯ АТАКА:{RESET}")
        if hg.get("is_idn"):
            print(f"     IDN/Punycode: {hg.get('punycode','')}")
        if hg.get("has_homograph"):
            print(f"     {RED}Омографы обнаружены! ASCII: {hg.get('ascii_equivalent','')}{RESET}")
        if hg.get("mixed_scripts"):
            print(f"     {RED}Смешанные скрипты (кирилл+латин) 🚨{RESET}")
        if hg.get("confusable_brand"):
            print(f"     {RED}Имитирует бренд: «{hg['confusable_brand']}» 🚨{RESET}")

    # ── GSB ──
    if gsb.get("gsb_enabled"):
        if gsb.get("gsb_threats"):
            print(f"  {RED}🔴 Google Safe Browsing: {', '.join(gsb['gsb_threats'])} 🚨{RESET}")
        else:
            print(f"  {GREEN}✅ Google Safe Browsing: чисто{RESET}")

    # ── Расширенный HTML ──
    js_score = h.get("js_obfuscation_score", 0)
    if js_score >= 25 or h.get("brand_title_mismatch") or h.get("clipboard_hijack") or h.get("fake_captcha"):
        print(f"  {'─'*58}")
        print(f"  📄 HTML дополнительно:")
        if js_score >= 25:
            c = RED if js_score >= 50 else YELLOW
            print(f"     {c}JS обфускация: {js_score}/100{RESET}")
        if h.get("brand_title_mismatch"):
            print(f"     {RED}Бренд в <title> не совпадает с доменом 🚨{RESET}")
        if h.get("clipboard_hijack"):
            print(f"     {RED}Перехват буфера обмена (clipboard) 🚨{RESET}")
        if h.get("fake_captcha"):
            print(f"     {RED}Поддельная CAPTCHA обнаружена 🚨{RESET}")
        if h.get("favicon_external"):
            print(f"     {YELLOW}Внешний favicon ⚠️{RESET}")

    # ── Новый вывод: анализ форм ──
    if h.get("forms_total", 0) > 0:
        danger = h.get("forms_danger_count", 0)
        ext    = h.get("forms_external",     0)
        ip_act = h.get("forms_ip_action",    0)
        print(f"  {'─'*58}")
        print(f"  📋 ФОРМЫ (action-анализ):")
        print(f"     Всего форм:          {h['forms_total']}")
        if ext > 0:
            print(f"     {RED}Внешний action:  {ext} ⚠️{RESET}")
        if ip_act > 0:
            print(f"     {RED}IP в action:     {ip_act} 🚨{RESET}")
        if h.get("forms_empty_action", 0) > 0:
            print(f"     {YELLOW}Пустой action:   {h['forms_empty_action']} ⚠️{RESET}")
        if h.get("forms_http_mixed", 0) > 0:
            print(f"     {YELLOW}HTTP на HTTPS:   {h['forms_http_mixed']} ⚠️{RESET}")
        # Детали каждой формы
        for i, form in enumerate(h.get("forms_analysis", [])[:5], 1):
            risk_color = RED if form["risk"] == "danger" else (YELLOW if form["risk"] == "warn" else GREEN)
            risk_icon  = "🚨" if form["risk"] == "danger" else ("⚠️" if form["risk"] == "warn" else "✅")
            action_str = (form.get("action") or "(пусто)")[:45]
            pwd_str    = " 🔑" if form.get("has_password") else ""
            print(f"     {risk_color}{risk_icon} Форма {i}:{RESET} {action_str}{pwd_str}")
            for flag in form.get("flags", []):
                print(f"        {DIM}↳ {flag}{RESET}")

    logos = h.get("brand_logos_found", [])
    if logos:
        print(f"  🏷  Логотипы   : {', '.join(logos)}")
    if t.get("is_typosquat"):
        print(f"  🔤 Typosquat   : ⚠️  имитирует «{t['impersonated_brand']}» (d={t['edit_distance']})")
    if vt.get("vt_enabled"):
        print(f"  🦠 VirusTotal  : {vt['vt_malicious']} вред / {vt['vt_suspicious']} подоз "
              f"из {vt['vt_total']}")
    print(f"{'─'*W}")
    print(f"  {icon} ВЕРДИКТ   : {color}{verdict}{RESET}")
    print(f"  🎯 Риск       : {risk}/100    🔮 Уверенность: {conf}%")
    print(f"{'─'*W}")
    if ai.get("red_flags"):
        print(f"  {RED}🚩 Тревожные признаки:{RESET}")
        for f_ in ai["red_flags"]:
            print(f"     • {f_}")
    if ai.get("green_flags"):
        print(f"  {GREEN}✔  Хорошие признаки:{RESET}")
        for f_ in ai["green_flags"]:
            print(f"     • {f_}")
    print(f"{'─'*W}")
    if ai.get("explanation"):
        print(f"  📝 {ai['explanation']}")
    if ai.get("recommendation"):
        print(f"  💡 {ai['recommendation']}")
    if ai.get("error"):
        print(f"  ❌ Ошибка AI: {ai['error']}")
    print(f"{'═'*W}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  ЭКСПОРТ
# ══════════════════════════════════════════════════════════════════════════════

def export_json(data: dict, ai: dict, url: str):
    os.makedirs(EXPORT_DIR, exist_ok=True)
    safe = re.sub(r"[^\w]", "_", url)[:50]
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(EXPORT_DIR, f"{safe}_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"collected": data, "ai_verdict": ai,
                   "checked_at": datetime.now().isoformat()}, f,
                  ensure_ascii=False, indent=2, default=str)
    print(f"  {DIM}📂 JSON сохранён: {path}{RESET}")
    return path


def export_html(data: dict, ai: dict, url: str):
    os.makedirs(EXPORT_DIR, exist_ok=True)
    safe = re.sub(r"[^\w]", "_", url)[:50]
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(EXPORT_DIR, f"{safe}_{ts}.html")

    verdict = ai.get("verdict", "ОШИБКА")
    color   = {"ФИШИНГ": "#e53e3e", "ПОДОЗРИТЕЛЬНО": "#d69e2e",
               "БЕЗОПАСНО": "#38a169"}.get(verdict, "#888")
    risk    = ai.get("risk_score", 0)
    b       = data.get("basic",       {})
    w       = data.get("whois",       {})
    s       = data.get("ssl",         {})
    h       = data.get("html",        {})
    vt      = data.get("virustotal",  {})

    def esc(v): return html.escape(str(v))
    def row(label, value):
        return f"<tr><td>{esc(label)}</td><td><b>{esc(value)}</b></td></tr>"

    red_rows   = "".join(f"<li>{esc(f)}</li>" for f in ai.get("red_flags",   []))
    green_rows = "".join(f"<li>{esc(f)}</li>" for f in ai.get("green_flags", []))

    # HTML-таблица форм
    forms_rows = ""
    for i, form in enumerate(h.get("forms_analysis", [])[:5], 1):
        risk_color = {"danger": "#e53e3e", "warn": "#d69e2e", "safe": "#38a169"}.get(form.get("risk","safe"), "#888")
        risk_label = {"danger": "опасно",  "warn": "внимание", "safe": "ок"}.get(form.get("risk","safe"), "?")
        flags      = ", ".join(form.get("flags", [])) or "—"
        pwd        = "да" if form.get("has_password") else "нет"
        action_str = esc(form.get("action") or "(пусто)")
        forms_rows += f"""<tr>
          <td style="color:{risk_color};font-weight:bold">{esc(risk_label)}</td>
          <td style="font-family:monospace;font-size:12px">{action_str}</td>
          <td>{esc(form.get('method','?'))}</td>
          <td>{pwd}</td>
          <td style="font-size:12px;color:#e53e3e">{esc(flags)}</td>
        </tr>"""

    forms_table = ""
    if h.get("forms_total", 0) > 0:
        forms_table = f"""
<div class="card">
  <h2>📋 Анализ форм (action)</h2>
  <table style="width:100%;border-collapse:collapse;font-size:13px;">
    <thead>
      <tr style="background:#f7f7f7;">
        <th style="padding:6px 8px;text-align:left;border-bottom:1px solid #eee;">Риск</th>
        <th style="padding:6px 8px;text-align:left;border-bottom:1px solid #eee;">action</th>
        <th style="padding:6px 8px;text-align:left;border-bottom:1px solid #eee;">Метод</th>
        <th style="padding:6px 8px;text-align:left;border-bottom:1px solid #eee;">Пароль</th>
        <th style="padding:6px 8px;text-align:left;border-bottom:1px solid #eee;">Флаги</th>
      </tr>
    </thead>
    <tbody>{forms_rows}</tbody>
  </table>
  <p style="font-size:12px;color:#888;margin-top:8px;">
    Всего форм: {h.get('forms_total',0)} &nbsp;|&nbsp;
    Внешних action: <b style="color:#e53e3e">{h.get('forms_external',0)}</b> &nbsp;|&nbsp;
    IP в action: <b style="color:#e53e3e">{h.get('forms_ip_action',0)}</b> &nbsp;|&nbsp;
    Опасных: <b style="color:#e53e3e">{h.get('forms_danger_count',0)}</b>
  </p>
</div>"""

    content = f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8">
<title>Phishing Report — {esc(url)}</title>
<style>
body{{font-family:system-ui,sans-serif;background:#f7f7f7;margin:0;padding:24px;color:#222}}
.card{{background:#fff;border-radius:12px;padding:24px;margin-bottom:20px;box-shadow:0 1px 6px #0001}}
h1{{font-size:20px;margin:0 0 4px}} h2{{font-size:15px;color:#555;margin:16px 0 8px}}
.verdict{{font-size:32px;font-weight:700;color:{color};margin:8px 0}}
.risk-bar{{height:12px;border-radius:6px;background:#eee;margin:8px 0}}
.risk-fill{{height:12px;border-radius:6px;background:{color};width:{risk}%}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
td,th{{padding:5px 8px;border-bottom:1px solid #f0f0f0;text-align:left}}
ul{{margin:4px 0;padding-left:20px;font-size:13px}} li{{margin:3px 0}}
.red{{color:#e53e3e}} .green{{color:#38a169}}
footer{{font-size:11px;color:#999;text-align:center;margin-top:16px}}
</style></head><body>
<div class="card">
  <h1>🛡 Phishing Site Detector v2.0</h1>
  <p style="color:#666;font-size:13px">Проверено: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}</p>
  <p style="font-size:14px">🌐 <b>{esc(url)}</b></p>
  <div class="verdict">{verdict}</div>
  <div class="risk-bar"><div class="risk-fill"></div></div>
  <p style="font-size:13px">Риск: <b>{risk}/100</b> · Уверенность AI: <b>{ai.get('confidence','?')}%</b></p>
  <p style="font-size:14px">{esc(ai.get('explanation',''))}</p>
  <p style="font-size:13px;background:#fffbe6;border-radius:6px;padding:8px">
    💡 {esc(ai.get('recommendation',''))}</p>
</div>
<div class="card">
  <h2>🔎 Данные о сайте</h2>
  <table>
    {row('IP-адрес', b.get('ip','н/д'))}
    {row('HTTP статус', b.get('status_code','н/д'))}
    {row('Заголовок', b.get('page_title','н/д'))}
    {row('SSL', '✅ ' + s.get('ssl_issuer','') if s.get('has_ssl') else '❌ Отсутствует')}
    {row('Дней до истечения SSL', s.get('ssl_days_left','н/д'))}
    {row('Возраст домена', str(w.get('domain_age_days','?')) + ' дней')}
    {row('Регистратор', w.get('registrar','н/д'))}
    {row('VirusTotal (вред/подоз/всего)', f"{vt.get('vt_malicious','-')}/{vt.get('vt_suspicious','-')}/{vt.get('vt_total','-')}")}
  </table>
</div>
{forms_table}
<div class="card">
  <h2 class="red">🚩 Тревожные признаки</h2>
  <ul class="red">{red_rows or '<li>нет</li>'}</ul>
  <h2 class="green">✔ Хорошие признаки</h2>
  <ul class="green">{green_rows or '<li>нет</li>'}</ul>
</div>
<footer>Phishing Detector v2.0 · OpenRouter AI · {MODEL}</footer>
</body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  {DIM}🌐 HTML отчёт: {path}{RESET}")
    return path


# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНАЯ ФУНКЦИЯ
# ══════════════════════════════════════════════════════════════════════════════

def check_url(url: str, use_cache=True, export=True):
    cache = _load_cache()
    key   = _cache_key(url)

    if use_cache and key in cache:
        entry = cache[key]
        age_h = (datetime.now().timestamp() - entry.get("ts", 0)) / 3600
        if age_h < 24:
            print(f"  {DIM}♻  Из кэша (проверялось {age_h:.1f} ч назад){RESET}")
            print_result(entry["data"], entry["ai"])
            return entry["ai"]

    print(f"\n  ⏳ Сбор данных (параллельно): {url}")
    data = collect_all(url)

    print(f"  🤖 Анализ через AI ({MODEL}) ...")
    ai = ask_ai(data)

    print_result(data, ai)

    if export:
        export_json(data, ai, url)
        export_html(data, ai, url)

    cache[key] = {"data": data, "ai": ai, "ts": datetime.now().timestamp()}
    _save_cache(cache)
    return ai


def check_file(filepath: str):
    """Пакетная проверка: один URL на строку в файле."""
    if not os.path.exists(filepath):
        print(f"❌ Файл не найден: {filepath}")
        return
    with open(filepath, encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    print(f"\n📋 Пакетная проверка: {len(urls)} URL из «{filepath}»")
    summary = []
    for i, url in enumerate(urls, 1):
        print(f"\n[{i}/{len(urls)}] {url}")
        ai = check_url(url)
        summary.append((url, ai.get("verdict","?"), ai.get("risk_score","?")))
    print(f"\n{'═'*62}")
    print(f"  📊 ИТОГ ПАКЕТНОЙ ПРОВЕРКИ")
    print(f"{'─'*62}")
    for url, verdict, risk in summary:
        c = {
            "ФИШИНГ": RED + BOLD, "ПОДОЗРИТЕЛЬНО": YELLOW + BOLD,
            "БЕЗОПАСНО": GREEN + BOLD
        }.get(verdict, BOLD)
        print(f"  {c}{verdict:15}{RESET}  риск {risk:>3}   {url}")
    print(f"{'═'*62}")


# ══════════════════════════════════════════════════════════════════════════════
#  ТОЧКА ВХОДА
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print(f"\n{'═'*62}")
    print(f"  {BOLD}🛡  PHISHING DETECTOR v2.0{RESET}  |  OpenRouter + VirusTotal")
    print(f"{'═'*62}")

    args = sys.argv[1:]

    if not args:
        print("\n  Режимы запуска:")
        print("   python phishing_checker_v2.py <url>")
        print("   python phishing_checker_v2.py <url1> <url2> ...")
        print("   python phishing_checker_v2.py --file urls.txt\n")
        raw = input("  🔗 Введи URL: ").strip()
        args = raw.split() if raw else []

    if not args:
        print("❌ URL не указан."); sys.exit(1)

    if args[0] == "--file" and len(args) > 1:
        check_file(args[1])
    else:
        for url in args:
            check_url(url)