from flask import Flask, render_template, request, jsonify, session, send_file
import hashlib
import bcrypt
import re
import time
import random
import string
from datetime import datetime, timedelta
from collections import defaultdict
import os
import json
import secrets
import pyotp
import qrcode
from io import BytesIO
import base64

app = Flask(__name__)
app.secret_key = 'vapt_security_project_2026'

# Global storage for demonstration
login_attempts = defaultdict(list)
user_accounts = {}
attack_logs = []
defense_enabled = False

# Persistence files (lightweight JSON storage for demo)
DATA_DIR = 'data'
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
LOGS_FILE = os.path.join(DATA_DIR, 'logs.json')


def ensure_data_dir():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)


def load_state():
    """Load persisted users and logs from disk (if present)"""
    global user_accounts, attack_logs
    ensure_data_dir()
    # Load users
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                user_accounts = json.load(f)
        except Exception:
            user_accounts = {}
    else:
        user_accounts = {}

    # Load logs
    if os.path.exists(LOGS_FILE):
        try:
            with open(LOGS_FILE, 'r') as f:
                attack_logs = json.load(f)
        except Exception:
            attack_logs = []
    else:
        attack_logs = []


def save_state():
    """Persist users and logs to disk (best-effort; intended for demo only)"""
    ensure_data_dir()
    try:
        # Debug: indicate save attempt
        print(f"Saving users to {USERS_FILE} (count={len(user_accounts)})")
        with open(USERS_FILE + '.tmp', 'w') as f:
            json.dump(user_accounts, f, indent=2)
        os.replace(USERS_FILE + '.tmp', USERS_FILE)
    except Exception as e:
        print('Failed to save users:', e)

    try:
        print(f"Saving logs to {LOGS_FILE} (count={len(attack_logs)})")
        with open(LOGS_FILE + '.tmp', 'w') as f:
            json.dump(attack_logs, f, indent=2)
        os.replace(LOGS_FILE + '.tmp', LOGS_FILE)
    except Exception as e:
        print('Failed to save logs:', e)

# Common passwords for dictionary attack
COMMON_PASSWORDS = []

def load_wordlist():
    """Load common passwords from wordlist file"""
    global COMMON_PASSWORDS
    try:
        with open('wordlist.txt', 'r') as f:
            COMMON_PASSWORDS = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        COMMON_PASSWORDS = ['password', '123456', 'admin', 'qwerty', 'letmein', 
                           'welcome', 'monkey', 'dragon', '111111', 'password123']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/password-strength', methods=['POST'])
def check_password_strength():
    """Analyze password strength and calculate crack time"""
    data = request.json
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    
    # Calculate strength metrics
    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    # Check against common passwords
    is_common = password.lower() in [p.lower() for p in COMMON_PASSWORDS[:100]]
    
    # Calculate score
    score = 0
    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if length >= 16:
        score += 1
    if has_upper:
        score += 1
    if has_lower:
        score += 1
    if has_digit:
        score += 1
    if has_special:
        score += 2
    
    if is_common:
        score = max(0, score - 3)
    
    # Determine strength
    if score <= 3:
        strength = 'Weak'
        color = 'danger'
    elif score <= 6:
        strength = 'Medium'
        color = 'warning'
    else:
        strength = 'Strong'
        color = 'success'
    
    # Calculate estimated crack time
    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_special:
        charset_size += 32
    
    if charset_size > 0:
        combinations = charset_size ** length
        # Assume 1 billion attempts per second
        seconds = combinations / 1_000_000_000
        crack_time = format_time(seconds)
    else:
        crack_time = "Instantly"
    
    if is_common:
        crack_time = "Instantly (Common Password)"
    
    return jsonify({
        'strength': strength,
        'score': score,
        'color': color,
        'length': length,
        'has_upper': has_upper,
        'has_lower': has_lower,
        'has_digit': has_digit,
        'has_special': has_special,
        'is_common': is_common,
        'crack_time': crack_time,
        'entropy': calculate_entropy(password)
    })

def format_time(seconds):
    """Format seconds into human-readable time"""
    if seconds < 1:
        return "Less than 1 second"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds / 3600)} hours"
    elif seconds < 31536000:
        return f"{int(seconds / 86400)} days"
    else:
        years = int(seconds / 31536000)
        if years > 1_000_000_000:
            return f"{years / 1_000_000_000:.2f} billion years"
        elif years > 1_000_000:
            return f"{years / 1_000_000:.2f} million years"
        return f"{years:,} years"

def calculate_entropy(password):
    """Calculate password entropy"""
    charset_size = 0
    if re.search(r'[a-z]', password):
        charset_size += 26
    if re.search(r'[A-Z]', password):
        charset_size += 26
    if re.search(r'\d', password):
        charset_size += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        charset_size += 32
    
    if charset_size > 0:
        import math
        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)
    return 0

@app.route('/api/generate-password', methods=['POST'])
def generate_password():
    """Generate a secure random password"""
    data = request.json
    length = int(data.get('length', 16))
    include_upper = data.get('include_upper', True)
    include_lower = data.get('include_lower', True)
    include_numbers = data.get('include_numbers', True)
    include_symbols = data.get('include_symbols', True)
    pronounceable = data.get('pronounceable', False)
    
    # Validate length
    length = max(8, min(length, 128))
    
    if pronounceable:
        # Generate pronounceable password
        consonants = 'bcdfghjklmnpqrstvwxyz'
        vowels = 'aeiou'
        password = ''
        for i in range(length):
            if i % 2 == 0:
                password += random.choice(consonants)
            else:
                password += random.choice(vowels)
        
        # Add numbers and symbols if requested
        if include_numbers:
            password = password[:-2] + str(random.randint(0, 99))
        if include_symbols:
            password = password + random.choice('!@#$%^&*')
    else:
        # Generate random password
        charset = ''
        if include_lower:
            charset += string.ascii_lowercase
        if include_upper:
            charset += string.ascii_uppercase
        if include_numbers:
            charset += string.digits
        if include_symbols:
            charset += '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        if not charset:
            charset = string.ascii_letters + string.digits
        
        password = ''.join(secrets.choice(charset) for _ in range(length))
    
    # Calculate strength
    strength_response = check_password_strength_internal(password)
    
    return jsonify({
        'password': password,
        'strength': strength_response
    })

def check_password_strength_internal(password):
    """Internal function to check password strength"""
    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    is_common = password.lower() in [p.lower() for p in COMMON_PASSWORDS[:100]]
    
    score = 0
    if length >= 8: score += 1
    if length >= 12: score += 1
    if length >= 16: score += 1
    if has_upper: score += 1
    if has_lower: score += 1
    if has_digit: score += 1
    if has_special: score += 2
    if is_common: score = max(0, score - 3)
    
    if score <= 3:
        strength = 'Weak'
        color = 'danger'
    elif score <= 6:
        strength = 'Medium'
        color = 'warning'
    else:
        strength = 'Strong'
        color = 'success'
    
    return {
        'strength': strength,
        'score': score,
        'color': color,
        'length': length,
        'has_upper': has_upper,
        'has_lower': has_lower,
        'has_digit': has_digit,
        'has_special': has_special,
        'is_common': is_common,
        'entropy': calculate_entropy(password)
    }

@app.route('/api/check-breach', methods=['POST'])
def check_breach():
    """Simulate checking if password has been in known data breaches"""
    data = request.json
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    
    # Simulate breach check (in real app, use haveibeenpwned API)
    # For demo, mark common passwords and simple patterns as breached
    is_breached = False
    breach_count = 0
    
    if password.lower() in [p.lower() for p in COMMON_PASSWORDS[:50]]:
        is_breached = True
        breach_count = random.randint(100000, 5000000)
    elif len(password) < 8:
        is_breached = True
        breach_count = random.randint(10000, 100000)
    elif password.isdigit() or password.isalpha():
        is_breached = True
        breach_count = random.randint(5000, 50000)
    
    return jsonify({
        'is_breached': is_breached,
        'breach_count': breach_count,
        'message': f'This password has been seen {breach_count:,} times in data breaches!' if is_breached else 'Good news! This password was not found in known data breaches.'
    })

@app.route('/api/2fa/generate', methods=['POST'])
def generate_2fa():
    """Generate 2FA secret and QR code"""
    data = request.json
    username = data.get('username', 'user@example.com')
    
    # Generate secret
    secret = pyotp.random_base32()
    
    # Generate QR code
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=username,
        issuer_name='VAPT Password Security'
    )
    
    # Create QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode()
    
    return jsonify({
        'secret': secret,
        'qr_code': f'data:image/png;base64,{qr_code_base64}',
        'provisioning_uri': provisioning_uri
    })

@app.route('/api/2fa/verify', methods=['POST'])
def verify_2fa():
    """Verify 2FA code"""
    data = request.json
    secret = data.get('secret', '')
    code = data.get('code', '')
    
    if not secret or not code:
        return jsonify({'error': 'Secret and code are required'}), 400
    
    try:
        totp = pyotp.TOTP(secret)
        is_valid = totp.verify(code, valid_window=1)
        
        return jsonify({
            'valid': is_valid,
            'message': 'Code verified successfully!' if is_valid else 'Invalid code. Please try again.'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/password-policy/check', methods=['POST'])
def check_password_policy():
    """Check password against custom policy"""
    data = request.json
    password = data.get('password', '')
    policy = data.get('policy', {})
    
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    
    violations = []
    passed = []
    
    # Check minimum length
    min_length = policy.get('min_length', 8)
    if len(password) < min_length:
        violations.append(f'Minimum length of {min_length} characters required')
    else:
        passed.append(f'Minimum length requirement met ({len(password)}/{min_length})')
    
    # Check maximum length
    max_length = policy.get('max_length', 128)
    if len(password) > max_length:
        violations.append(f'Maximum length of {max_length} characters exceeded')
    else:
        passed.append(f'Maximum length requirement met ({len(password)}/{max_length})')
    
    # Check uppercase
    if policy.get('require_uppercase', False):
        if not re.search(r'[A-Z]', password):
            violations.append('At least one uppercase letter required')
        else:
            passed.append('Contains uppercase letters')
    
    # Check lowercase
    if policy.get('require_lowercase', False):
        if not re.search(r'[a-z]', password):
            violations.append('At least one lowercase letter required')
        else:
            passed.append('Contains lowercase letters')
    
    # Check numbers
    if policy.get('require_numbers', False):
        if not re.search(r'\d', password):
            violations.append('At least one number required')
        else:
            passed.append('Contains numbers')
    
    # Check special characters
    if policy.get('require_special', False):
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            violations.append('At least one special character required')
        else:
            passed.append('Contains special characters')
    
    # Check no common passwords
    if policy.get('no_common_passwords', False):
        if password.lower() in [p.lower() for p in COMMON_PASSWORDS[:100]]:
            violations.append('Password is too common')
        else:
            passed.append('Not a common password')
    
    # Check no repeated characters
    if policy.get('no_repeated_chars', False):
        if re.search(r'(.)\1{2,}', password):
            violations.append('No more than 2 repeated characters allowed')
        else:
            passed.append('No excessive repeated characters')
    
    # Check no sequential characters
    if policy.get('no_sequential', False):
        for i in range(len(password) - 2):
            if ord(password[i]) + 1 == ord(password[i+1]) and ord(password[i+1]) + 1 == ord(password[i+2]):
                violations.append('Sequential characters not allowed (e.g., abc, 123)')
                break
        else:
            passed.append('No sequential characters')
    
    is_compliant = len(violations) == 0
    
    return jsonify({
        'compliant': is_compliant,
        'violations': violations,
        'passed': passed,
        'score': len(passed) / (len(passed) + len(violations)) * 100 if (len(passed) + len(violations)) > 0 else 0
    })

@app.route('/api/export/json', methods=['GET'])
def export_json():
    """Export security data as JSON"""
    data = {
        'export_date': datetime.now().isoformat(),
        'statistics': {
            'total_users': len(user_accounts),
            'total_login_attempts': sum(len(attempts) for attempts in login_attempts.values()),
            'locked_accounts': sum(1 for user in user_accounts.values() if user.get('locked', False)),
            'total_security_events': len(attack_logs)
        },
        'users': [
            {
                'username': username,
                'created_at': user.get('created_at'),
                'locked': user.get('locked', False),
                'failed_attempts': user.get('failed_attempts', 0)
            }
            for username, user in user_accounts.items()
        ],
        'security_logs': attack_logs[-100:],  # Last 100 logs
        'defense_status': {
            'enabled': defense_enabled,
            'features': [
                'Account Lockout (3 attempts)',
                'Rate Limiting (5 attempts per 5 minutes)',
                'Login Delay',
                'Real-time Monitoring'
            ]
        }
    }
    
    return jsonify(data)

@app.route('/api/hash-password', methods=['POST'])
def hash_password():
    """Demonstrate password hashing with multiple algorithms"""
    data = request.json
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    
    # Generate different hashes
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    bcrypt_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    return jsonify({
        'plain': password,
        'sha256': sha256_hash,
        'md5': md5_hash,
        'bcrypt': bcrypt_hash,
        'sha256_length': len(sha256_hash),
        'bcrypt_length': len(bcrypt_hash)
    })

@app.route('/api/brute-force', methods=['POST'])
def brute_force_attack():
    """Simulate brute force attack"""
    data = request.json
    target_password = data.get('password', '')
    max_length = min(int(data.get('max_length', 4)), 6)  # Limit for demo
    
    if not target_password:
        return jsonify({'error': 'Password is required'}), 400
    
    start_time = time.time()
    attempts = 0
    found = False
    cracked_password = None
    
    # Try common patterns first
    common_patterns = ['123', 'abc', 'password', 'admin', '111', 'aaa']
    for pattern in common_patterns:
        attempts += 1
        if pattern == target_password:
            found = True
            cracked_password = pattern
            break
    
    # Brute force with limited charset
    if not found and len(target_password) <= max_length:
        charset = string.ascii_lowercase + string.digits
        for length in range(1, max_length + 1):
            if attempts > 10000:  # Limit for demo
                break
            
            # Try limited combinations
            for i in range(min(1000, len(charset) ** length)):
                attempts += 1
                # Generate candidate
                candidate = ''.join(random.choice(charset) for _ in range(length))
                
                if candidate == target_password:
                    found = True
                    cracked_password = candidate
                    break
            
            if found:
                break
    
    elapsed_time = time.time() - start_time
    
    return jsonify({
        'success': found,
        'attempts': attempts,
        'time': round(elapsed_time, 3),
        'cracked_password': cracked_password,
        'rate': round(attempts / elapsed_time) if elapsed_time > 0 else 0
    })

@app.route('/api/dictionary-attack', methods=['POST'])
def dictionary_attack():
    """Simulate dictionary attack"""
    data = request.json
    target_password = data.get('password', '')
    
    if not target_password:
        return jsonify({'error': 'Password is required'}), 400
    
    start_time = time.time()
    attempts = 0
    found = False
    cracked_password = None
    
    # Try each word in dictionary
    for word in COMMON_PASSWORDS:
        attempts += 1
        if word == target_password:
            found = True
            cracked_password = word
            break
        
        # Try with common variations
        variations = [
            word,
            word.upper(),
            word.capitalize(),
            word + '123',
            word + '!',
            '123' + word
        ]
        
        for variation in variations:
            attempts += 1
            if variation == target_password:
                found = True
                cracked_password = variation
                break
        
        if found:
            break
    
    elapsed_time = time.time() - start_time
    
    return jsonify({
        'success': found,
        'attempts': attempts,
        'time': round(elapsed_time, 3),
        'cracked_password': cracked_password,
        'dictionary_size': len(COMMON_PASSWORDS),
        'rate': round(attempts / elapsed_time) if elapsed_time > 0 else 0
    })

@app.route('/api/register', methods=['POST'])
def register():
    """Register a test user account"""
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    if username in user_accounts:
        return jsonify({'error': 'User already exists'}), 400
    
    # Store password hash
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user_accounts[username] = {
        'password_hash': password_hash,
        'created_at': datetime.now().isoformat(),
        'locked': False,
        'failed_attempts': 0
    }
    # Persist users for demo persistence across restarts
    save_state()

    return jsonify({
        'success': True,
        'message': f'User {username} registered successfully'
    })

@app.route('/api/login', methods=['POST'])
def login():
    """Simulate login with defense mechanisms"""
    global defense_enabled
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')
    source_ip = request.remote_addr
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    # Check if user exists
    if username not in user_accounts:
        log_attack('Login attempt', username, source_ip, False, 'User not found')
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    
    user = user_accounts[username]
    
    # Defense Mechanism 1: Account Lockout
    if defense_enabled and user.get('locked', False):
        log_attack('Login attempt', username, source_ip, False, 'Account locked')
        return jsonify({
            'success': False,
            'message': 'Account is locked due to too many failed attempts',
            'blocked': True
        }), 403
    
    # Defense Mechanism 2: Rate Limiting
    if defense_enabled:
        recent_attempts = [
            t for t in login_attempts[username]
            if datetime.fromisoformat(t) > datetime.now() - timedelta(minutes=5)
        ]
        
        if len(recent_attempts) >= 5:
            log_attack('Login attempt', username, source_ip, False, 'Rate limit exceeded')
            return jsonify({
                'success': False,
                'message': 'Too many login attempts. Please try again later.',
                'blocked': True
            }), 429
    
    # Record login attempt
    login_attempts[username].append(datetime.now().isoformat())
    
    # Defense Mechanism 3: Time delay (simulation)
    if defense_enabled:
        time.sleep(0.5)  # Small delay
    
    # Verify password
    try:
        password_match = bcrypt.checkpw(password.encode(), user['password_hash'].encode())
    except:
        password_match = False
    
    if password_match:
        # Successful login
        user['failed_attempts'] = 0
        user['locked'] = False
        log_attack('Login success', username, source_ip, True, 'Valid credentials')
        return jsonify({
            'success': True,
            'message': 'Login successful'
        })
    else:
        # Failed login
        user['failed_attempts'] = user.get('failed_attempts', 0) + 1
        
        # Lock account after 3 failed attempts (if defense enabled)
        if defense_enabled and user['failed_attempts'] >= 3:
            user['locked'] = True
            log_attack('Account locked', username, source_ip, False, f"{user['failed_attempts']} failed attempts")
            return jsonify({
                'success': False,
                'message': 'Account has been locked due to multiple failed attempts',
                'blocked': True
            }), 403
        
        log_attack('Login failed', username, source_ip, False, 'Invalid password')
        return jsonify({
            'success': False,
            'message': f'Invalid credentials. {3 - user["failed_attempts"]} attempts remaining' if defense_enabled else 'Invalid credentials'
        }), 401

@app.route('/api/toggle-defense', methods=['POST'])
def toggle_defense():
    """Toggle defense mechanisms on/off"""
    global defense_enabled
    data = request.json
    defense_enabled = data.get('enabled', False)
    
    # Reset all account locks and attempts
    for user in user_accounts.values():
        user['locked'] = False
        user['failed_attempts'] = 0
    
    login_attempts.clear()
    # Persist state after toggling defense
    save_state()
    
    return jsonify({
        'success': True,
        'defense_enabled': defense_enabled,
        'message': f'Defense mechanisms {"enabled" if defense_enabled else "disabled"}'
    })

@app.route('/api/attack-logs', methods=['GET'])
def get_attack_logs():
    """Get attack logs"""
    return jsonify({
        'logs': attack_logs[-50:],  # Last 50 logs
        'total': len(attack_logs)
    })

@app.route('/api/clear-logs', methods=['POST'])
def clear_logs():
    """Clear attack logs"""
    global attack_logs
    attack_logs = []
    save_state()
    return jsonify({'success': True, 'message': 'Logs cleared'})

@app.route('/api/reset-accounts', methods=['POST'])
def reset_accounts():
    """Reset all user accounts"""
    global user_accounts, login_attempts
    user_accounts = {}
    login_attempts.clear()
    save_state()
    return jsonify({'success': True, 'message': 'All accounts reset'})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get system statistics"""
    total_attempts = sum(len(attempts) for attempts in login_attempts.values())
    locked_accounts = sum(1 for user in user_accounts.values() if user.get('locked', False))
    
    return jsonify({
        'total_users': len(user_accounts),
        'total_login_attempts': total_attempts,
        'locked_accounts': locked_accounts,
        'defense_enabled': defense_enabled,
        'total_logs': len(attack_logs)
    })

def log_attack(event_type, username, source_ip, success, details):
    """Log security event"""
    attack_logs.append({
        'timestamp': datetime.now().isoformat(),
        'type': event_type,
        'username': username,
        'source_ip': source_ip,
        'success': success,
        'details': details
    })
    # Persist logs so they survive server restarts (demo purpose)
    try:
        save_state()
    except Exception:
        pass

if __name__ == '__main__':
    # Load persisted state and wordlist
    load_state()
    load_wordlist()
    print("🔐 Password Security & Credential Attack Detection System")
    print("=" * 60)
    print("Server starting at http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, port=5000)
