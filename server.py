from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import json
import os
import sys
import re
import requests
import sqlite3
from urllib.parse import urlparse
from datetime import datetime
from contextlib import contextmanager
from dotenv import load_dotenv  # ← Добавляем импорт

# Загружаем переменные из .env
load_dotenv()

# Import parser module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parser import (
    _load_cache, _save_cache, _cache_key,
    collect_all, ask_ai, print_result,
    module_basic, module_ssl, module_whois, module_dns, module_html,
    module_typosquatting, module_virustotal, module_homograph, module_safe_browsing
)

# ─── КОНФИГУРАЦИЯ (БЕЗОПАСНО) ──────────────────────────────────────────────────
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY") # ← Берем из .env
MODEL = "google/gemini-2.5-flash-lite"
# Database file
DATABASE_FILE = "phishing.db"

app = Flask(__name__, template_folder='.', static_folder='.')
CORS(app)

# ===========================
# DATABASE FUNCTIONS (НОВЫЕ)
# ===========================

def init_database():
    """Initialize SQLite database"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS phishing_sites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL UNIQUE,
                domain TEXT NOT NULL,
                risk_score INTEGER DEFAULT 0,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                verdict TEXT DEFAULT 'ФИШИНГ',
                explanation TEXT,
                checked_at TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS stats (
                stat_key TEXT PRIMARY KEY,
                stat_value INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT OR IGNORE INTO stats (stat_key, stat_value) 
            VALUES ('total_checks', 0), ('total_phishing', 0)
        ''')
        
        conn.commit()
        print("✓ Database initialized")

@contextmanager
def get_db():
    """Context manager for database connections"""
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def add_phishing_site(url, domain, risk_score, details, ai_analysis):
    """Add a phishing site to database"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT id FROM phishing_sites WHERE url = ?", (url,))
            existing = cursor.fetchone()
            
            if existing:
                cursor.execute('''
                    UPDATE phishing_sites 
                    SET risk_score = ?, verdict = ?, explanation = ?, checked_at = ?
                    WHERE id = ?
                ''', (risk_score, 'ФИШИНГ', ai_analysis.get('explanation', '')[:500], 
                      datetime.now().isoformat(), existing['id']))
            else:
                cursor.execute('''
                    INSERT INTO phishing_sites (url, domain, risk_score, verdict, explanation, checked_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (url, domain, risk_score, 'ФИШИНГ', 
                      ai_analysis.get('explanation', '')[:500], datetime.now().isoformat()))
            
            cursor.execute('''
                UPDATE stats SET stat_value = stat_value + 1, updated_at = CURRENT_TIMESTAMP
                WHERE stat_key = 'total_phishing'
            ''')
            
            conn.commit()
            return True
    except Exception as e:
        print(f"Error adding phishing site: {e}")
        return False

def update_check_stats():
    """Update total checks counter"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE stats SET stat_value = stat_value + 1, updated_at = CURRENT_TIMESTAMP
                WHERE stat_key = 'total_checks'
            ''')
            conn.commit()
    except Exception as e:
        print(f"Error updating stats: {e}")

def get_stats():
    """Get statistics"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT stat_key, stat_value FROM stats")
            stats = {row['stat_key']: row['stat_value'] for row in cursor.fetchall()}
            return stats
    except Exception as e:
        print(f"Error getting stats: {e}")
        return {'total_checks': 0, 'total_phishing': 0}

def get_phishing_sites(limit=100):
    """Get list of phishing sites"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, url, domain, risk_score, detected_at, verdict, explanation
                FROM phishing_sites
                ORDER BY detected_at DESC
                LIMIT ?
            ''', (limit,))
            sites = [dict(row) for row in cursor.fetchall()]
            
            cursor.execute("SELECT COUNT(*) as total FROM phishing_sites")
            total = cursor.fetchone()['total']
            
            return sites, total
    except Exception as e:
        print(f"Error getting phishing sites: {e}")
        return [], 0

# Initialize database
init_database()

# ===========================
# ROUTES (ВСЕ СУЩЕСТВУЮЩИЕ + НОВЫЕ)
# ===========================

@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/index.html')
def index_html():
    """Serve index page"""
    return render_template('index.html')

@app.route('/search.html')
def search():
    """Serve the search page"""
    return render_template('search.html')

@app.route('/chat.html')
def chat():
    """Serve the chat page"""
    return render_template('chat.html')

@app.route('/what-is-phishing.html')
def what_is_phishing():
    """Serve the phishing information page"""
    return render_template('what-is-phishing.html')

@app.route('/about.html')
def about():
    """Serve the about page"""
    return render_template('about.html')

@app.route('/phishing.html')
def phishing():
    """Serve the phishing database page"""
    return render_template('phishing.html')

@app.route('/style.css')
def serve_css():
    """Serve CSS file"""
    return send_file('style.css', mimetype='text/css')

@app.route('/scripts.js')
def serve_js():
    """Serve JavaScript file"""
    return send_file('scripts.js', mimetype='text/javascript')

@app.route('/images/<filename>')
def serve_image(filename):
    """Serve images"""
    return send_file(f'images/{filename}')

# ===========================
# API ROUTES (НОВЫЕ)
# ===========================

@app.route('/api/phishing/list', methods=['GET'])
def get_phishing_list():
    """Get list of phishing sites"""
    try:
        limit = request.args.get('limit', 100, type=int)
        sites, total = get_phishing_sites(limit)
        
        last_updated = None
        if sites:
            last_updated = sites[0].get('detected_at')
        
        return jsonify({
            'success': True,
            'total': total,
            'sites': sites,
            'last_updated': last_updated
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats_api():
    """Get system statistics"""
    try:
        stats = get_stats()
        return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ===========================
# API CHAT (ОРИГИНАЛЬНЫЙ, НЕ МЕНЯЛ)
# ===========================

@app.route('/api/chat', methods=['POST'])
def chat_api():
    """Proxy for OpenRouter API to avoid CORS and provide chat functionality"""
    try:
        data = request.get_json()
        user_message = data.get('message', '')
        history = data.get('history', [])
        
        if not user_message:
            return jsonify({'error': 'Сообщение не может быть пустым'}), 400
        
        system_prompt = """Ты — Fish Hunter AI, экспертный консультант по кибербезопасности и защите от фишинга. 
Твоя задача — помогать пользователям разбираться в вопросах кибербезопасности, фишинга, защиты персональных данных, безопасного поведения в интернете.
Отвечай на русском языке подробно, но по существу. Будь дружелюбным и профессиональным.
Если пользователь спрашивает не о кибербезопасности, вежливо предложи вернуться к теме защиты от фишинга.
Ты представляешь сервис Fish Hunter — систему обнаружения фишинга на основе искусственного интеллекта."""
        
        messages = [{"role": "system", "content": system_prompt}]
        
        if history and len(history) > 0:
            messages.extend(history[-10:])
        
        messages.append({"role": "user", "content": user_message})
        
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://fish-hunter.local",
                "X-Title": "Fish Hunter Chat"
            },
            json={
                "model": MODEL,
                "messages": messages,
                "temperature": 0.7,
                "max_tokens": 1000,
                "top_p": 0.9
            },
            timeout=45
        )
        
        if response.status_code != 200:
            error_data = response.json() if response.text else {}
            print(f"OpenRouter API error: {response.status_code} - {error_data}")
            return jsonify({
                'error': f'API error: {response.status_code}',
                'details': error_data
            }), response.status_code
        
        result = response.json()
        ai_response = result.get('choices', [{}])[0].get('message', {}).get('content', '')
        
        if not ai_response:
            return jsonify({'error': 'Пустой ответ от API'}), 500
        
        return jsonify({
            'success': True,
            'response': ai_response,
            'model': MODEL
        })
        
    except requests.exceptions.Timeout:
        return jsonify({'error': 'Превышено время ожидания ответа от API'}), 504
    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")
        return jsonify({'error': f'Ошибка соединения: {str(e)}'}), 500
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Внутренняя ошибка сервера: {str(e)}'}), 500

# ===========================
# CHECK URL (ПОЛНОСТЬЮ СОХРАНЕН)
# ===========================

@app.route('/check', methods=['POST'])
def check_url():
    """
    Check URL for phishing using full parser analysis
    Returns comprehensive phishing detection results
    """
    try:
        data = request.get_json()
        url = data.get('url', '').strip()

        if not url:
            return jsonify({
                'success': False,
                'error': 'URL не предоставлен'
            }), 400

        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        # Update statistics (НОВОЕ)
        update_check_stats()

        # Check cache
        cache = _load_cache()
        cache_key = _cache_key(url)
        
        if cache_key in cache:
            cached_result = cache[cache_key]
            if 'full_analysis' in cached_result:
                return jsonify({
                    'success': True,
                    'from_cache': True,
                    **cached_result['full_analysis']
                })

        print(f"\n  ⏳ Collecting data for: {url}")
        analysis_data = collect_all(url)
        
        print(f"  🤖 AI Analysis via OpenRouter...")
        ai_result = ask_ai(analysis_data)
        
        # Extract data from analysis
        basic = analysis_data.get('basic', {})
        ssl = analysis_data.get('ssl', {})
        whois = analysis_data.get('whois', {})
        dns = analysis_data.get('dns', {})
        html = analysis_data.get('html', {})
        typo = analysis_data.get('typo', {})
        vt = analysis_data.get('virustotal', {})
        hg = analysis_data.get('homograph', {})
        gsb = analysis_data.get('safe_browsing', {})
        
        risk_score = 0
        risk_factors = []
        
        # SSL check
        if not ssl.get('has_ssl'):
            risk_score += 25
            risk_factors.append('Отсутствует SSL сертификат')
        elif ssl.get('ssl_days_left') and ssl.get('ssl_days_left') < 7:
            risk_score += 15
            risk_factors.append('SSL сертификат истекает')
            
        # Domain age
        domain_age = whois.get('domain_age_days')
        if domain_age and domain_age < 30:
            risk_score += 30
            risk_factors.append(f'Домен зарегистрирован недавно ({domain_age} дней)')
        elif domain_age and domain_age < 90:
            risk_score += 15
            risk_factors.append(f'Домен относительно новый ({domain_age} дней)')
            
        # IP in URL
        if basic.get('has_ip_in_url'):
            risk_score += 35
            risk_factors.append('IP-адрес вместо домена')
            
        # Suspicious keywords in URL
        suspicious_keywords = basic.get('suspicious_keywords', [])
        if suspicious_keywords:
            risk_score += min(len(suspicious_keywords) * 10, 30)
            risk_factors.append(f'Подозрительные слова в URL: {", ".join(suspicious_keywords)}')
            
        # Login form without SSL
        if html.get('has_login_form') and not ssl.get('has_ssl'):
            risk_score += 30
            risk_factors.append('Форма входа без SSL шифрования')
            
        # Password forms count
        password_forms = html.get('password_forms', 0)
        if password_forms > 0:
            risk_score += min(password_forms * 10, 25)
            
        # Meta refresh (redirects)
        if html.get('meta_refresh'):
            risk_score += 20
            risk_factors.append('Meta refresh редирект')
            
        # Obfuscated JavaScript
        if html.get('obfuscated_js'):
            risk_score += 20
            risk_factors.append('Обфусцированный JavaScript код')
            
        # External scripts
        external_scripts = html.get('external_scripts', 0)
        if external_scripts > 10:
            risk_score += 15
            risk_factors.append(f'Много внешних скриптов ({external_scripts})')
            
        # Hidden iframes
        hidden_iframes = html.get('hidden_iframes', 0)
        if hidden_iframes > 0:
            risk_score += 25
            risk_factors.append(f'Скрытые iframe ({hidden_iframes})')
            
        # Brand logos
        brand_logos = html.get('brand_logos_found', [])
        if brand_logos:
            risk_score += 20
            risk_factors.append(f'Логотипы брендов на странице: {", ".join(brand_logos)}')
            
        # Forms analysis
        forms_danger = html.get('forms_danger_count', 0)
        forms_external = html.get('forms_external', 0)
        forms_ip_action = html.get('forms_ip_action', 0)
        
        if forms_danger > 0:
            risk_score += forms_danger * 20
            risk_factors.append(f'Опасные формы ({forms_danger})')
        if forms_external > 0:
            risk_score += forms_external * 15
            risk_factors.append(f'Формы с внешним action ({forms_external})')
        if forms_ip_action > 0:
            risk_score += 30
            risk_factors.append(f'IP-адрес в action формы')
            
        # DNS security
        if not dns.get('has_spf'):
            risk_score += 10
            risk_factors.append('Отсутствует SPF запись')
        if not dns.get('has_dmarc'):
            risk_score += 10
            risk_factors.append('Отсутствует DMARC запись')
            
        # Typosquatting
        if typo.get('is_typosquat'):
            risk_score += 40
            risk_factors.append(f'Typosquatting: имитирует бренд "{typo.get("impersonated_brand", "")}"')
            
        # Homograph attack
        if hg.get('has_homograph') or hg.get('is_idn'):
            risk_score += 50
            risk_factors.append('Гомографическая атака (IDN/омографы)')
        elif hg.get('mixed_scripts'):
            risk_score += 30
            risk_factors.append('Смешанные скрипты в домене')
            
        # Google Safe Browsing
        if gsb.get('gsb_enabled') and gsb.get('gsb_threats'):
            risk_score += 50
            risk_factors.append(f'В Google Safe Browsing: {", ".join(gsb["gsb_threats"])}')
            
        # VirusTotal
        if vt.get('vt_enabled'):
            vt_malicious = vt.get('vt_malicious', 0)
            if vt_malicious > 0:
                risk_score += min(vt_malicious * 10, 50)
                risk_factors.append(f'VirusTotal: {vt_malicious} вредоносных определений')
                
        # JS Obfuscation score
        js_score = html.get('js_obfuscation_score', 0)
        if js_score >= 50:
            risk_score += 25
            risk_factors.append(f'Высокий уровень обфускации JS ({js_score}/100)')
        elif js_score >= 25:
            risk_score += 12
            risk_factors.append(f'Средний уровень обфускации JS ({js_score}/100)')
            
        # Brand in title mismatch
        if html.get('brand_title_mismatch'):
            risk_score += 35
            risk_factors.append('Бренд в заголовке не соответствует домену')
            
        # Clipboard hijack
        if html.get('clipboard_hijack'):
            risk_score += 30
            risk_factors.append('Перехват буфера обмена')
            
        # Fake captcha
        if html.get('fake_captcha'):
            risk_score += 30
            risk_factors.append('Поддельная CAPTCHA')
            
        # External favicon
        if html.get('favicon_external'):
            risk_score += 10
            risk_factors.append('Внешний favicon')

        # Final verdict
        is_phishing = risk_score >= 40
        
        if is_phishing:
            verdict = "ФИШИНГ"
            verdict_color = "danger"
            verdict_text = "Обнаружен фишинг"
            message = f"ВНИМАНИЕ! Обнаружены признаки фишинга (уровень риска: {min(100, risk_score)}%)"
        elif risk_score >= 20:
            verdict = "ПОДОЗРИТЕЛЬНО"
            verdict_color = "warning"
            verdict_text = "Подозрительный сайт"
            message = f"Сайт вызывает подозрение (уровень риска: {min(100, risk_score)}%)"
        else:
            verdict = "БЕЗОПАСНО"
            verdict_color = "safe"
            verdict_text = "Сайт безопасен"
            message = f"Сайт выглядит безопасно (уровень риска: {min(100, risk_score)}%)"
            
        result = {
            'success': True,
            'from_cache': False,
            'url': url,
            'domain': analysis_data.get('domain', ''),
            'is_phishing': is_phishing,
            'verdict': verdict,
            'verdict_color': verdict_color,
            'verdict_text': verdict_text,
            'risk_score': min(100, risk_score),
            'confidence': ai_result.get('confidence', 70 if is_phishing else 85),
            'message': message,
            'ai_analysis': ai_result,
            'details': {
                'basic': {
                    'ip': basic.get('ip', 'н/д'),
                    'status_code': basic.get('status_code'),
                    'page_title': basic.get('page_title', 'н/д')[:100],
                    'final_url': basic.get('final_url', url),
                    'redirects': basic.get('redirects', []),
                    'has_ip_in_url': basic.get('has_ip_in_url', False),
                    'domain_length': basic.get('domain_length', 0),
                    'suspicious_keywords': basic.get('suspicious_keywords', [])
                },
                'ssl': {
                    'has_ssl': ssl.get('has_ssl', False),
                    'ssl_issuer': ssl.get('ssl_issuer', ''),
                    'ssl_subject': ssl.get('ssl_subject', ''),
                    'ssl_expires': ssl.get('ssl_expires', ''),
                    'ssl_days_left': ssl.get('ssl_days_left')
                },
                'whois': {
                    'domain_age_days': whois.get('domain_age_days'),
                    'registrar': whois.get('registrar', ''),
                    'creation_date': whois.get('creation_date', ''),
                    'country': whois.get('country', '')
                },
                'dns': {
                    'has_mx': dns.get('has_mx', False),
                    'has_spf': dns.get('has_spf', False),
                    'has_dmarc': dns.get('has_dmarc', False),
                    'mx_records': dns.get('mx_records', [])
                },
                'html': {
                    'password_forms': html.get('password_forms', 0),
                    'hidden_iframes': html.get('hidden_iframes', 0),
                    'external_links': html.get('external_links', 0),
                    'external_scripts': html.get('external_scripts', 0),
                    'brand_logos_found': html.get('brand_logos_found', []),
                    'has_login_form': html.get('has_login_form', False),
                    'obfuscated_js': html.get('obfuscated_js', False),
                    'meta_refresh': html.get('meta_refresh', False),
                    'js_obfuscation_score': html.get('js_obfuscation_score', 0),
                    'brand_in_title': html.get('brand_in_title', False),
                    'brand_title_mismatch': html.get('brand_title_mismatch', False),
                    'favicon_external': html.get('favicon_external', False),
                    'favicon_url': html.get('favicon_url', ''),
                    'clipboard_hijack': html.get('clipboard_hijack', False),
                    'fake_captcha': html.get('fake_captcha', False),
                    'forms_total': html.get('forms_total', 0),
                    'forms_external': html.get('forms_external', 0),
                    'forms_ip_action': html.get('forms_ip_action', 0),
                    'forms_empty_action': html.get('forms_empty_action', 0),
                    'forms_danger_count': html.get('forms_danger_count', 0),
                    'forms_analysis': html.get('forms_analysis', [])
                },
                'typosquatting': {
                    'is_typosquat': typo.get('is_typosquat', False),
                    'closest_brand': typo.get('closest_brand', ''),
                    'impersonated_brand': typo.get('impersonated_brand', ''),
                    'edit_distance': typo.get('edit_distance', 99)
                },
                'homograph': {
                    'is_idn': hg.get('is_idn', False),
                    'has_homograph': hg.get('has_homograph', False),
                    'mixed_scripts': hg.get('mixed_scripts', False),
                    'punycode': hg.get('punycode', ''),
                    'ascii_equivalent': hg.get('ascii_equivalent', ''),
                    'confusable_brand': hg.get('confusable_brand', ''),
                    'homograph_risk': hg.get('homograph_risk', 'safe')
                },
                'virustotal': {
                    'vt_enabled': vt.get('vt_enabled', False),
                    'vt_malicious': vt.get('vt_malicious', 0),
                    'vt_suspicious': vt.get('vt_suspicious', 0),
                    'vt_harmless': vt.get('vt_harmless', 0),
                    'vt_total': vt.get('vt_total', 0)
                },
                'safe_browsing': {
                    'gsb_enabled': gsb.get('gsb_enabled', False),
                    'gsb_threats': gsb.get('gsb_threats', [])
                }
            },
            'risk_factors': risk_factors[:10],
            'green_flags': ai_result.get('green_flags', []),
            'explanation': ai_result.get('explanation', ''),
            'recommendation': ai_result.get('recommendation', ''),
            'checked_at': datetime.now().isoformat()
        }
        
        # Cache the result
        cache[cache_key] = {
            'full_analysis': result,
            'ts': datetime.now().timestamp()
        }
        _save_cache(cache)
        
        # НОВОЕ: Если сайт фишинговый, добавляем в БД
        if result.get('is_phishing'):
            add_phishing_site(
                url=result['url'],
                domain=result['domain'],
                risk_score=result['risk_score'],
                details=result['details'],
                ai_analysis=result.get('ai_analysis', {})
            )
        
        return jsonify(result)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
        return jsonify({'status': 'ok', 'database': 'connected'})
    except Exception as e:
        return jsonify({'status': 'error', 'database': str(e)}), 500

# ===========================
# ERROR HANDLERS
# ===========================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Server error'}), 500

# ===========================
# RUN
# ===========================

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  FISH HUNTER - Anti-Phishing System")
    print("="*60)
    print("  Server starting at http://localhost:5000")
    print("  Search page: http://localhost:5000/search.html")
    print("  Chat page: http://localhost:5000/chat.html")
    print("  About phishing: http://localhost:5000/what-is-phishing.html")
    print("  About service: http://localhost:5000/about.html")
    print("  Phishing DB: http://localhost:5000/phishing.html")
    print("="*60 + "\n")
    app.run(debug=True, port=5000, host='0.0.0.0')