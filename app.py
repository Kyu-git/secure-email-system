from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from werkzeug.security import generate_password_hash, check_password_hash
from flask import send_from_directory, Response
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
from flask_login import login_required, current_user, login_user, logout_user
from flask_login import LoginManager
from your_user_model import User 
from datetime import timedelta
from functools import wraps

import traceback
import binascii  # for hex conversion
import sqlite3
import os
import datetime
import re
import csv
from io import StringIO

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB limit
app.config['SECRET_KEY'] = 'your-secret-key-here'  # one can Change this to a secure secret key
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'

DB_NAME = 'users.db'
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Profile picture upload configuration
PROFILE_PICTURE_FOLDER = 'static/profile_pictures'
ALLOWED_PROFILE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif'}
app.config['PROFILE_PICTURE_FOLDER'] = PROFILE_PICTURE_FOLDER

# Create uploads folder if not exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Create profile pictures folder if not exists
if not os.path.exists(PROFILE_PICTURE_FOLDER):
    os.makedirs(PROFILE_PICTURE_FOLDER)

ALLOWED_EXTENSIONS = {'.pdf', '.png', '.jpg', '.jpeg', '.docx'}


# --- Initialize DB ---
def init_db():
    if not os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        # Users table
        c.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fullname TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                is_approved BOOLEAN DEFAULT FALSE,
                profile_picture TEXT,
                bio TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Emails table
        c.execute('''
            CREATE TABLE emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                subject TEXT,
                message TEXT,
                attachment TEXT,
                signature TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Rejected Emails table
        c.execute('''
            CREATE TABLE rejected_emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT,
                recipient TEXT,
                subject TEXT,
                message TEXT,
                reason TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # FAQs table
        c.execute('''
            CREATE TABLE faqs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                question TEXT NOT NULL,
                answer TEXT NOT NULL,
                category TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Help Requests table
        c.execute('''
            CREATE TABLE help_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                subject TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                admin_response TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        conn.commit()
        conn.close()
        print("✅ Database created with users, emails, rejected_emails, faqs, and help_requests tables.")

def is_allowed_file(filename):
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS

def allowed_profile_file(filename):
    return os.path.splitext(filename)[1].lower() in ALLOWED_PROFILE_EXTENSIONS

def is_suspicious_url(url):
    parsed = urlparse(url)
    
    # Block non-HTTPS links
    if parsed.scheme != 'https':
        return True
    
    # Block IP-based URLs
    if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc):
        return True
    
    # Known phishing domains (should be updated regularly in production)
    blacklist = [
        'phishing.com', 'malicious.net', 'scam.org', 'fake-login',
        'account-verify', 'secure-login', 'banking-secure',
        'bit.ly', 'goo.gl', 'tinyurl.com', 'is.gd', 'ow.ly'  # URL shorteners
    ]
    
    # Check against blacklist using partial matching
    if any(bad_domain in parsed.netloc.lower() for bad_domain in blacklist):
        return True
    
    # Check for spoofing attempts (e.g., mail-go0gle.com)
    popular_domains = [
        'google', 'facebook', 'microsoft', 'apple', 'amazon',
        'paypal', 'netflix', 'twitter', 'instagram', 'linkedin',
        'bank', 'chase', 'wellsfargo', 'citi', 'boa'
    ]
    
    # Get the full domain
    full_domain = parsed.netloc.lower()
    
    # Check for domain spoofing
    for domain in popular_domains:
        # Create variations with common character substitutions
        substitutions = {
            'o': ['0', 'o0'],
            'i': ['1', 'i1'],
            'e': ['3', 'e3'],
            'a': ['4', 'a4'],
            's': ['5', 's5'],
            'g': ['6', 'g6', '9', 'g9'],
            't': ['7', 't7'],
            'b': ['8', 'b8'],
            'l': ['1', 'l1']
        }
        
        # Create a regex pattern that matches the domain with possible substitutions
        pattern = domain
        for char, subs in substitutions.items():
            pattern = pattern.replace(char, f'[{char}{"".join(subs)}]')
        
        # Check if the pattern matches anywhere in the domain
        if re.search(pattern, full_domain):
            return True
            
        # Check for hyphen-based spoofing
        if f"-{domain}" in full_domain or f"{domain}-" in full_domain:
            return True
    
    # Check for fake links (e.g., paypal.com.verify-user-account.info)
    if re.search(r'\.(com|net|org|edu|gov)(\.[a-z]{2,}){2,}', parsed.netloc):
        return True
    
    # Check for suspicious patterns in URL
    suspicious_patterns = [
        r'bank.*\..*\.',  # Multiple subdomains with 'bank'
        r'secure.*\..*\.',  # Multiple subdomains with 'secure'
        r'account.*\..*\.',  # Multiple subdomains with 'account'
        r'login.*\..*\.',   # Multiple subdomains with 'login'
        r'verify.*\..*\.',  # Multiple subdomains with 'verify'
        r'update.*\..*\.',  # Multiple subdomains with 'update'
        r'confirm.*\..*\.', # Multiple subdomains with 'confirm'
        r'validate.*\..*\.', # Multiple subdomains with 'validate'
        r'security.*\..*\.', # Multiple subdomains with 'security'
        r'payment.*\..*\.',  # Multiple subdomains with 'payment'
        r'customer.*\..*\.', # Multiple subdomains with 'customer'
        r'service.*\..*\.',  # Multiple subdomains with 'service'
        r'support.*\..*\.',  # Multiple subdomains with 'support'
        r'help.*\..*\.',     # Multiple subdomains with 'help'
        r'portal.*\..*\.',   # Multiple subdomains with 'portal'
        r'access.*\..*\.',   # Multiple subdomains with 'access'
        r'admin.*\..*\.',    # Multiple subdomains with 'admin'
        r'user.*\..*\.',     # Multiple subdomains with 'user'
        r'profile.*\..*\.',  # Multiple subdomains with 'profile'
        r'settings.*\..*\.', # Multiple subdomains with 'settings'
        r'password.*\..*\.', # Multiple subdomains with 'password'
        r'reset.*\..*\.',    # Multiple subdomains with 'reset'
        r'change.*\..*\.',   # Multiple subdomains with 'change'
    ]
    
    if any(re.search(pattern, parsed.netloc.lower()) for pattern in suspicious_patterns):
        return True
    
    # Check for URL shorteners in the path
    if re.search(r'/(bit\.ly|goo\.gl|tinyurl\.com|is\.gd|ow\.ly)/', url.lower()):
        return True
    
    # Check for excessive subdomains
    if len(parsed.netloc.split('.')) > 3:
        return True
    
    return False

def check_for_spam(sender, subject, message, attachment_filename=None):
    reasons = []
    
    # Advanced keyword-based detection
    suspicious_keywords = [
        'urgent', 'click here', 'verify your account', 'password reset', 'bank', 'ssn',
        'account suspended', 'lottery', 'winner', 'inheritance', 'million dollars',
        'cryptocurrency', 'investment opportunity', 'free money', 'gift card',
        'account security', 'unusual activity', 'login attempt'
    ]
    
    # Check subject for spam indicators
    subject_lower = subject.lower()
    if any(keyword in subject_lower for keyword in suspicious_keywords):
        reasons.append("Suspicious keywords in subject")
    
    if subject.isupper():
        reasons.append("Subject is all uppercase (potential spam)")
    
    # Check message content
    message_lower = message.lower()
    if any(keyword in message_lower for keyword in suspicious_keywords):
        reasons.append("Suspicious keywords in message body")
    
    # Check for excessive punctuation
    if message.count('!') > 3 or message.count('$') > 2:
        reasons.append("Excessive punctuation (potential spam indicator)")
    
    # Detect suspicious URLs
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', message)
    
    if len(urls) > 5:
        reasons.append("Too many URLs in message")
    
    for url in urls:
        if is_suspicious_url(url):
            reasons.append(f"Suspicious URL detected: {url}")
    
    # Check for potential phishing indicators
    phishing_phrases = [
        'verify your account',
        'confirm your identity',
        'update your information',
        'unusual activity',
        'account suspended'
    ]
    
    if any(phrase in message_lower for phrase in phishing_phrases):
        reasons.append("Potential phishing attempt detected")
    
    # Check attachment if present
    if attachment_filename:
        # Check file extension
        _, ext = os.path.splitext(attachment_filename)
        dangerous_extensions = ['.exe', '.bat', '.cmd', '.sh', '.js', '.vbs', '.ps1', '.msi', '.dll']
        if ext.lower() in dangerous_extensions:
            reasons.append(f"Dangerous file type detected: {ext}")
            
        # Check for double extensions (e.g., file.jpg.exe)
        if attachment_filename.count('.') > 1:
            reasons.append("Multiple file extensions detected (potential malware)")
            
        # Check file size limit (5MB)
        # Note: Actual file size check is done by Flask's MAX_CONTENT_LENGTH
        
    return reasons


@app.route('/download_attachment/<filename>')
def download_attachment(filename):
    if 'email' not in session:
        return redirect('/login')

    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Make sure current user is the recipient of the file
        c.execute('SELECT * FROM emails WHERE attachment = ? AND recipient = ?', 
                  (os.path.join(app.config['UPLOAD_FOLDER'], filename), session['email']))
        email = c.fetchone()
        conn.close()

        if email:
            return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
        else:
            return "Unauthorized access", 403
    except Exception as e:
        print("Download error:", str(e))
        return "Error downloading file", 500



# --- Home route ---
@app.route('/')
def home():
    return render_template('index.html')

@login_manager.user_loader
def load_user(user_id):
    return User.get(int(user_id))

# --- Registration page ---
@app.route('/register')
def register_page():
    return render_template('register.html')

# --- Login page ---
@app.route('/login')
def login_page():
    return render_template('login.html')

# --- Logout route ---
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login_page'))

# --- Dashboard (Inbox) page ---
@app.route('/dashboard')
@login_required
def dashboard():
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM emails WHERE recipient = ? ORDER BY timestamp DESC', (current_user.email,))
        inbox_messages = c.fetchall()
        conn.close()

        verified_messages = []
        for email in inbox_messages:
            try:
                sender = email['sender']
                signature_hex = email['signature']
                message_data = f"{email['sender']}|{email['recipient']}|{email['subject']}|{email['message']}".encode()

                # Load sender's public key
                public_key_path = f'keys/{sender}_public.pem'
                if not os.path.exists(public_key_path):
                    email_dict = dict(email)
                    email_dict['verification_status'] = 'No public key found'
                    email_dict['is_verified'] = False
                    verified_messages.append(email_dict)
                    continue

                with open(public_key_path, "rb") as key_file:
                    public_key = serialization.load_pem_public_key(key_file.read())

                # Verify signature
                try:
                    public_key.verify(
                        bytes.fromhex(signature_hex),
                        message_data,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    email_dict = dict(email)
                    email_dict['verification_status'] = 'Signature verified'
                    email_dict['is_verified'] = True
                    verified_messages.append(email_dict)
                except Exception:
                    email_dict = dict(email)
                    email_dict['verification_status'] = 'Invalid signature'
                    email_dict['is_verified'] = False
                    verified_messages.append(email_dict)

            except Exception as e:
                email_dict = dict(email)
                email_dict['verification_status'] = f'Verification error: {str(e)}'
                email_dict['is_verified'] = False
                verified_messages.append(email_dict)

        return render_template('inbox.html', 
                            name=current_user.fullname, 
                            email=current_user.email, 
                            inbox=verified_messages)
    except Exception as e:
        print("Dashboard error:", str(e))
        return render_template('inbox.html', 
                            name=current_user.fullname, 
                            email=current_user.email, 
                            inbox=[])

# --- Profile page ---
@app.route('/profile')
@login_required
def profile():
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get user data with all fields
        cursor.execute('''
            SELECT fullname, email, is_admin, is_approved, profile_picture, bio, last_updated 
            FROM users 
            WHERE id = ?
        ''', (current_user.id,))
        user_data = cursor.fetchone()
        
        conn.close()
        
        if user_data:
            return render_template('profile.html',
                                name=user_data['fullname'],
                                email=user_data['email'],
                                is_admin=user_data['is_admin'],
                                is_approved=user_data['is_approved'],
                                profile_picture=user_data['profile_picture'],
                                bio=user_data['bio'],
                                last_updated=user_data['last_updated'])
        else:
            return render_template('profile.html',
                                name=current_user.fullname,
                                email=current_user.email,
                                is_admin=False,
                                is_approved=False,
                                profile_picture=None,
                                bio=None,
                                last_updated=None)
    except Exception as e:
        print("Profile error:", str(e))
        return render_template('profile.html',
                            name=current_user.fullname,
                            email=current_user.email,
                            is_admin=False,
                            is_approved=False,
                            profile_picture=None,
                            bio=None,
                            last_updated=None)

# --- Attack Report page ---
@app.route('/attack_report')
@login_required
def attack_report():
    try:
        # Get date filters from query parameters
        start_date = request.args.get('start')
        end_date = request.args.get('end')
        
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Base query
        query = '''
            SELECT *, 
            CASE 
                WHEN reason LIKE '%phishing%' THEN 'Phishing'
                WHEN reason LIKE '%malware%' OR reason LIKE '%dangerous file%' THEN 'Malware'
                ELSE 'Spam'
            END as type
            FROM rejected_emails
            WHERE sender = ? OR recipient = ?
        '''
        
        params = [current_user.email, current_user.email]
        if start_date and end_date:
            query += ' AND date(timestamp) BETWEEN ? AND ?'
            params.extend([start_date, end_date])
            
        query += ' ORDER BY timestamp DESC'
        
        c.execute(query, params)
        rejected_emails = c.fetchall()
        
        # Calculate statistics
        stats = {
            'total_attacks': len(rejected_emails),
            'spam_attempts': sum(1 for email in rejected_emails if 'Spam' in email['type']),
            'phishing_attempts': sum(1 for email in rejected_emails if 'Phishing' in email['type']),
            'malware_detected': sum(1 for email in rejected_emails if 'Malware' in email['type'])
        }
        
        conn.close()
        
        return render_template('attack_report.html', 
                             attacks=rejected_emails,
                             stats=stats,
                             name=current_user.fullname)
                             
    except Exception as e:
        print("Attack report error:", str(e))
        return render_template('attack_report.html', 
                             attacks=[],
                             stats={'total_attacks': 0, 'spam_attempts': 0, 
                                   'phishing_attempts': 0, 'malware_detected': 0},
                             name=current_user.fullname)

@app.route('/download_attack_report')
@login_required
def download_attack_report():
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        # Get all rejected emails with attack type classification
        c.execute('''
            SELECT 
                timestamp,
                CASE 
                    WHEN reason LIKE '%phishing%' THEN 'Phishing'
                    WHEN reason LIKE '%malware%' OR reason LIKE '%dangerous file%' THEN 'Malware'
                    ELSE 'Spam'
                END as attack_type,
                sender,
                recipient,
                subject,
                reason
            FROM rejected_emails 
            ORDER BY timestamp DESC
        ''')
        
        rows = c.fetchall()
        conn.close()
        
        # Create CSV in memory
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Timestamp', 'Attack Type', 'Sender', 'Recipient', 'Subject', 'Reason'])
        writer.writerows(rows)
        
        # Create the response
        output.seek(0)
        return Response(
            output,
            mimetype="text/csv",
            headers={
                "Content-Disposition": f"attachment;filename=attack_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            }
        )
        
    except Exception as e:
        print("CSV export error:", str(e))
        return "Error generating report", 500


# --- Sent emails page ---
@app.route('/sent')
@login_required
def sent():
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM emails WHERE sender = ? ORDER BY timestamp DESC', (current_user.email,))
        sent_emails = c.fetchall()
        conn.close()
        return render_template('sent.html', name=current_user.fullname, email=current_user.email, emails=sent_emails)
    except Exception as e:
        print("Sent email load error:", str(e))
        return render_template('sent.html', name=current_user.fullname, email=current_user.email, emails=[])

# --- Compose Email page ---
@app.route('/compose')
@login_required
def compose():
    return render_template('compose.html', name=current_user.fullname, email=current_user.email)

# --- Registration API ---
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

# --- Key Pair Generation Function ---
def generate_key_pair(email):
    os.makedirs('keys', exist_ok=True)
    private_key_path = f'keys/{email}_private.pem'
    public_key_path = f'keys/{email}_public.pem'

    # Skip generation if keys already exist
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(public_key_path, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def validate_password(password):
    """
    Validate password against security rules:
    - At least 8 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one number
    - Contains at least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is valid"

# --- Registration API ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    fullName = data.get('fullName')
    email = data.get('email')
    password = data.get('password')

    if not all([fullName, email, password]):
        return jsonify({'error': 'All fields are required'}), 400

    # Validate email format
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({'error': 'Invalid email format'}), 400

    # Validate password strength
    if not re.match(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", password):
        return jsonify({'error': 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character'}), 400

    conn = sqlite3.connect(DB_NAME)
    try:
        # Check if email already exists
        cursor = conn.execute('SELECT id FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            return jsonify({'error': 'Email already registered'}), 400

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Insert new user with is_approved set to False
        conn.execute('''
            INSERT INTO users (fullname, email, password, is_admin, is_approved)
            VALUES (?, ?, ?, ?, ?)
        ''', (fullName, email, hashed_password, False, False))
        conn.commit()

        return jsonify({'message': 'Registration successful. Please wait for admin approval before logging in.'}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({'error': 'Registration failed. Please try again.'}), 500
    finally:
        conn.close()


# --- Login API ---
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT id, email, password, is_admin, is_approved FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if user and check_password_hash(user[2], password):
            # Check if user is approved
            if not user[4]:  # is_approved is False
                return jsonify({'error': 'Your account is pending admin approval'}), 403
                
            # Get the user object using our User model
            user_obj = User.get(user[0])
            if user_obj:
                # Log in the user
                login_user(user_obj)
                
                # Check if user is admin and redirect accordingly
                if user_obj.is_admin:
                    return jsonify({'redirect': '/admin'})
                else:
                    return jsonify({'redirect': '/dashboard'})
        return jsonify({'error': 'Invalid email or password'}), 401
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()



# --- Send Email API ---
@app.route('/api/send_email', methods=['POST'])
@login_required
def send_email():
    try:
        sender = current_user.email
        recipient = request.form.get('to')
        subject = request.form.get('subject')
        message = request.form.get('message')
        file = request.files.get('attachment')

        reasons = check_for_spam(sender, subject, message, file.filename if file else None)
        if reasons:
            reason_text = "; ".join(reasons)
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute('''
                INSERT INTO rejected_emails (sender, recipient, subject, message, reason)
                VALUES (?, ?, ?, ?, ?)
            ''', (sender, recipient, subject, message, reason_text))
            conn.commit()
            conn.close()
            return jsonify({'error': f'Message rejected: {reason_text}'}), 400

        if file and not is_allowed_file(file.filename):
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute('''
                INSERT INTO rejected_emails (sender, recipient, subject, message, reason)
                VALUES (?, ?, ?, ?, ?)
            ''', (sender, recipient, subject, message, 'Disallowed file type'))
            conn.commit()
            conn.close()
            return jsonify({'error': 'Only safe file types are allowed.'}), 400

        # Save Attachment
        attachment_path = None
        if file and file.filename != '':
            from uuid import uuid4
            filename = f"{uuid4().hex}_{secure_filename(file.filename)}"
            attachment_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(attachment_path)

        # Load Private Key
        private_key_path = f'keys/{sender}_private.pem'
        if not os.path.exists(private_key_path):
            return jsonify({'error': 'Private key not found'}), 500

        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)

        # Sign Email Data
        data_to_sign = f"{sender}|{recipient}|{subject}|{message}".encode()
        signature = private_key.sign(
            data_to_sign,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        signature_hex = signature.hex()

        # Save Email to DB
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''
            INSERT INTO emails (sender, recipient, subject, message, attachment, signature)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (sender, recipient, subject, message, attachment_path, signature_hex))
        conn.commit()
        conn.close()

        return jsonify({'message': 'Email sent and signed successfully'}), 200

    except Exception as e:
        print("Send email error:", str(e))
        traceback.print_exc()
        return jsonify({'error': 'Failed to send email'}), 500



# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(f"Admin required decorator called for {f.__name__}")
        print(f"Current user: {current_user}")
        print(f"Current user is authenticated: {current_user.is_authenticated}")
        
        # Check if user is authenticated first
        if not current_user.is_authenticated:
            print("User not authenticated, redirecting to login")
            return redirect(url_for('login_page'))
            
        # Now safely check if user is admin
        if not getattr(current_user, 'is_admin', False):
            print("User not authorized as admin, redirecting to login")
            return redirect(url_for('login_page'))
            
        return f(*args, **kwargs)
    return decorated_function

# Admin routes
@app.route('/admin')
@admin_required
def admin_dashboard():
    print("Admin dashboard route called")
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Get all users
        c.execute('SELECT id, fullname, email, created_at FROM users ORDER BY id')
        users = c.fetchall()
        
        # Get all attacks with statistics
        c.execute('''
            SELECT *, 
            CASE 
                WHEN reason LIKE '%phishing%' THEN 'Phishing'
                WHEN reason LIKE '%malware%' OR reason LIKE '%dangerous file%' THEN 'Malware'
                ELSE 'Spam'
            END as type
            FROM rejected_emails 
            ORDER BY timestamp DESC
        ''')
        attacks = c.fetchall()
        
        # Calculate statistics
        stats = {
            'total_users': len(users),
            'total_attacks': len(attacks),
            'spam_attempts': sum(1 for attack in attacks if 'Spam' in attack['type']),
            'phishing_attempts': sum(1 for attack in attacks if 'Phishing' in attack['type']),
            'malware_detected': sum(1 for attack in attacks if 'Malware' in attack['type'])
        }
        
        conn.close()
        
        return render_template('admin/dashboard.html', 
                             users=users,
                             attacks=attacks,
                             stats=stats)
    except Exception as e:
        print(f"Admin dashboard error: {str(e)}")
        return render_template('admin/dashboard.html', 
                             users=[],
                             attacks=[],
                             stats={'total_users': 0, 'total_attacks': 0, 
                                   'spam_attempts': 0, 'phishing_attempts': 0, 
                                   'malware_detected': 0})

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard_redirect():
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/<int:user_id>/approve', methods=['POST'])
@admin_required
def approve_user(user_id):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Update user approval status
        cursor.execute('UPDATE users SET is_approved = TRUE WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'User approved successfully'})
    except Exception as e:
        print(f"Approve user error: {str(e)}")
        return jsonify({'error': 'Failed to approve user'}), 500

@app.route('/admin/users')
@admin_required
def admin_users():
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Get search parameters
        search_query = request.args.get('search', '')
        status = request.args.get('status', '')
        page = int(request.args.get('page', 1))
        per_page = 10
        
        # Base query
        query = 'SELECT id, fullname, email, created_at, is_admin, is_approved FROM users'
        count_query = 'SELECT COUNT(*) FROM users'
        params = []
        
        # Add status filter if provided
        if status:
            if status == 'pending':
                query += ' WHERE is_approved = FALSE'
                count_query += ' WHERE is_approved = FALSE'
            elif status == 'approved':
                query += ' WHERE is_approved = TRUE'
                count_query += ' WHERE is_approved = TRUE'
            elif status == 'rejected':
                query += ' WHERE is_approved = FALSE'
                count_query += ' WHERE is_approved = FALSE'
        
        # Add search filter if provided
        if search_query:
            if status:
                query += ' AND (fullname LIKE ? OR email LIKE ?)'
                count_query += ' AND (fullname LIKE ? OR email LIKE ?)'
            else:
                query += ' WHERE fullname LIKE ? OR email LIKE ?'
                count_query += ' WHERE fullname LIKE ? OR email LIKE ?'
            params.extend([f'%{search_query}%', f'%{search_query}%'])
        
        # Add pagination
        query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'
        params.extend([per_page, (page - 1) * per_page])
        
        # Get total count for pagination
        c.execute(count_query, params[:-2] if search_query else [])
        total_users = c.fetchone()[0]
        total_pages = (total_users + per_page - 1) // per_page
        
        # Get users
        c.execute(query, params)
        users = c.fetchall()
        
        # Convert created_at to datetime objects
        users = [dict(user) for user in users]
        for user in users:
            if user['created_at']:
                user['created_at'] = datetime.datetime.strptime(user['created_at'], '%Y-%m-%d %H:%M:%S')
        
        conn.close()
        
        return render_template('admin/users.html', 
                             users=users,
                             search_query=search_query,
                             status=status,
                             page=page,
                             total_pages=total_pages,
                             total_users=total_users)
    except Exception as e:
        print("Admin users error:", str(e))
        return render_template('admin/users.html', 
                             users=[],
                             search_query='',
                             status='',
                             page=1,
                             total_pages=1,
                             total_users=0)

@app.route('/admin/user/<int:user_id>/activity')
@admin_required
def admin_user_activity(user_id):
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Get user info
        c.execute('SELECT id, fullname, email, created_at FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        
        if not user:
            return redirect(url_for('admin_users'))
        
        # Get user's sent emails
        c.execute('''
            SELECT * FROM emails 
            WHERE sender = ? 
            ORDER BY timestamp DESC
        ''', (user['email'],))
        sent_emails = c.fetchall()
        
        # Get user's received emails
        c.execute('''
            SELECT * FROM emails 
            WHERE recipient = ? 
            ORDER BY timestamp DESC
        ''', (user['email'],))
        received_emails = c.fetchall()
        
        # Get user's rejected emails
        c.execute('''
            SELECT * FROM rejected_emails 
            WHERE sender = ? OR recipient = ? 
            ORDER BY timestamp DESC
        ''', (user['email'], user['email']))
        rejected_emails = c.fetchall()
        
        # Calculate statistics
        stats = {
            'total_sent': len(sent_emails),
            'total_received': len(received_emails),
            'total_rejected': len(rejected_emails),
            'spam_attempts': sum(1 for email in rejected_emails if 'Spam' in email['reason']),
            'phishing_attempts': sum(1 for email in rejected_emails if 'Phishing' in email['reason']),
            'malware_detected': sum(1 for email in rejected_emails if 'Malware' in email['reason'])
        }
        
        conn.close()
        
        return render_template('admin/user_activity.html',
                             user=user,
                             sent_emails=sent_emails,
                             received_emails=received_emails,
                             rejected_emails=rejected_emails,
                             stats=stats)
    except Exception as e:
        print("User activity error:", str(e))
        return redirect(url_for('admin_users'))

@app.route('/admin/system_activity')
@admin_required
def admin_system_activity():
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Get date filters
        start_date = request.args.get('start')
        end_date = request.args.get('end')
        
        # Base query for system-wide statistics
        query = '''
            SELECT 
                date(timestamp) as date,
                COUNT(*) as total_emails,
                SUM(CASE WHEN reason LIKE '%phishing%' THEN 1 ELSE 0 END) as phishing_count,
                SUM(CASE WHEN reason LIKE '%malware%' OR reason LIKE '%dangerous file%' THEN 1 ELSE 0 END) as malware_count,
                SUM(CASE WHEN reason NOT LIKE '%phishing%' AND reason NOT LIKE '%malware%' AND reason NOT LIKE '%dangerous file%' THEN 1 ELSE 0 END) as spam_count
            FROM rejected_emails
        '''
        
        params = []
        if start_date and end_date:
            query += ' WHERE date(timestamp) BETWEEN ? AND ?'
            params = [start_date, end_date]
            
        query += ' GROUP BY date(timestamp) ORDER BY date DESC'
        
        c.execute(query, params)
        daily_stats = c.fetchall()
        
        # Get top senders of rejected emails
        c.execute('''
            SELECT sender, COUNT(*) as count
            FROM rejected_emails
            GROUP BY sender
            ORDER BY count DESC
            LIMIT 10
        ''')
        top_senders = c.fetchall()
        
        # Get top recipients of rejected emails
        c.execute('''
            SELECT recipient, COUNT(*) as count
            FROM rejected_emails
            GROUP BY recipient
            ORDER BY count DESC
            LIMIT 10
        ''')
        top_recipients = c.fetchall()
        
        conn.close()
        
        return render_template('admin/system_activity.html',
                             daily_stats=daily_stats,
                             top_senders=top_senders,
                             top_recipients=top_recipients,
                             start_date=start_date,
                             end_date=end_date)
    except Exception as e:
        print("System activity error:", str(e))
        return render_template('admin/system_activity.html',
                             daily_stats=[],
                             top_senders=[],
                             top_recipients=[],
                             start_date=None,
                             end_date=None)

@app.route('/admin/user/<int:user_id>/toggle-admin', methods=['POST'])
@admin_required
def toggle_admin_status(user_id):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Get current admin status
        cursor.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
        current_status = cursor.fetchone()
        
        if not current_status:
            return jsonify({'error': 'User not found'}), 404
            
        # Toggle admin status
        new_status = not bool(current_status[0])
        cursor.execute('UPDATE users SET is_admin = ? WHERE id = ?', (new_status, user_id))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Admin status updated successfully'})
    except Exception as e:
        print(f"Toggle admin error: {str(e)}")
        return jsonify({'error': 'Failed to update admin status'}), 500

@app.route('/api/update_profile', methods=['POST'])
@login_required
def update_profile():
    try:
        # Get form data
        fullname = request.form.get('fullname')
        bio = request.form.get('bio')
        profile_picture = request.files.get('profile_picture')
        
        # Validate required fields
        if not fullname:
            return jsonify({'error': 'Full name is required'}), 400
        
        conn = None
        try:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            
            # Update basic profile info
            c.execute('''
                UPDATE users 
                SET fullname = ?, bio = ?, last_updated = datetime("now")
                WHERE id = ?
            ''', (fullname, bio, current_user.id))
            
            # Handle profile picture upload
            if profile_picture and profile_picture.filename:
                if not allowed_profile_file(profile_picture.filename):
                    return jsonify({'error': 'Invalid file type. Allowed types: PNG, JPG, JPEG, GIF'}), 400
                
                # Generate unique filename
                filename = f"{current_user.id}_{secure_filename(profile_picture.filename)}"
                filepath = os.path.join(app.config['PROFILE_PICTURE_FOLDER'], filename)
                
                # Save the file
                profile_picture.save(filepath)
                
                # Update database with new picture path
                c.execute('''
                    UPDATE users 
                    SET profile_picture = ? 
                    WHERE id = ?
                ''', (filename, current_user.id))
            
            conn.commit()
            return jsonify({'message': 'Profile updated successfully'}), 200
            
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            print(f"Database error: {str(e)}")
            return jsonify({'error': 'Database error occurred'}), 500
        finally:
            if conn:
                conn.close()
                
    except Exception as e:
        print("Profile update error:", str(e))
        return jsonify({'error': 'Failed to update profile'}), 500

def migrate_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    try:
        # Check if columns exist
        c.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in c.fetchall()]
        
        # Add new columns if they don't exist
        if 'profile_picture' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN profile_picture TEXT')
        if 'bio' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN bio TEXT')
        if 'created_at' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP')
            # Update existing rows with current timestamp
            c.execute('UPDATE users SET created_at = datetime("now") WHERE created_at IS NULL')
        if 'last_updated' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN last_updated DATETIME DEFAULT CURRENT_TIMESTAMP')
            # Update existing rows with current timestamp
            c.execute('UPDATE users SET last_updated = datetime("now") WHERE last_updated IS NULL')
        if 'is_approved' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN is_approved BOOLEAN DEFAULT FALSE')
            # Set all existing users as approved
            c.execute('UPDATE users SET is_approved = TRUE WHERE is_approved IS NULL')
        
        # Check if faqs table exists
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='faqs'")
        if not c.fetchone():
            c.execute('''
                CREATE TABLE faqs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    question TEXT NOT NULL,
                    answer TEXT NOT NULL,
                    category TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            print("✅ Created FAQs table")
        
        # Check if help_requests table exists
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='help_requests'")
        if not c.fetchone():
            c.execute('''
                CREATE TABLE help_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    subject TEXT NOT NULL,
                    message TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    admin_response TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            print("✅ Created help_requests table")
        
        conn.commit()
        print("✅ Database migration completed successfully")
    except Exception as e:
        print(f"❌ Database migration error: {str(e)}")
    finally:
        conn.close()

# Help and FAQ routes
@app.route('/help')
@login_required
def help_page():
    return redirect(url_for('help_request'))

@app.route('/help/request')
@login_required
def help_request():
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Get user's help requests
        c.execute('''
            SELECT hr.*, u.fullname 
            FROM help_requests hr 
            JOIN users u ON hr.user_id = u.id 
            WHERE hr.user_id = ? 
            ORDER BY hr.created_at DESC
        ''', (current_user.id,))
        help_requests = c.fetchall()
        
        conn.close()
        
        return render_template('help_request.html',
                             name=current_user.fullname,
                             help_requests=help_requests)
    except Exception as e:
        print("Help request page error:", str(e))
        return render_template('help_request.html',
                             name=current_user.fullname,
                             help_requests=[])

@app.route('/help/faqs')
@login_required
def faqs():
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Get all FAQs
        c.execute('SELECT * FROM faqs ORDER BY category, created_at DESC')
        faqs = c.fetchall()
        
        conn.close()
        
        return render_template('faqs.html',
                             name=current_user.fullname,
                             faqs=faqs)
    except Exception as e:
        print("FAQs page error:", str(e))
        return render_template('faqs.html',
                             name=current_user.fullname,
                             faqs=[])

@app.route('/api/submit_help_request', methods=['POST'])
@login_required
def submit_help_request():
    try:
        data = request.get_json()
        subject = data.get('subject')
        message = data.get('message')
        
        if not subject or not message:
            return jsonify({'error': 'Subject and message are required'}), 400
        
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        c.execute('''
            INSERT INTO help_requests (user_id, subject, message)
            VALUES (?, ?, ?)
        ''', (current_user.id, subject, message))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Help request submitted successfully'}), 200
    except Exception as e:
        print("Submit help request error:", str(e))
        return jsonify({'error': 'Failed to submit help request'}), 500

# Admin routes for managing FAQs and help requests
@app.route('/admin/faqs')
@admin_required
def admin_faqs():
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('SELECT * FROM faqs ORDER BY category, created_at DESC')
        faqs = c.fetchall()
        
        conn.close()
        
        return render_template('admin/faqs.html', faqs=faqs)
    except Exception as e:
        print("Admin FAQs error:", str(e))
        return render_template('admin/faqs.html', faqs=[])

@app.route('/api/admin/faq', methods=['POST'])
@admin_required
def add_faq():
    try:
        data = request.get_json()
        question = data.get('question')
        answer = data.get('answer')
        category = data.get('category')
        
        if not all([question, answer, category]):
            return jsonify({'error': 'All fields are required'}), 400
        
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        c.execute('''
            INSERT INTO faqs (question, answer, category)
            VALUES (?, ?, ?)
        ''', (question, answer, category))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'FAQ added successfully'}), 200
    except Exception as e:
        print("Add FAQ error:", str(e))
        return jsonify({'error': 'Failed to add FAQ'}), 500

@app.route('/api/admin/faq/<int:faq_id>', methods=['PUT', 'DELETE'])
@admin_required
def manage_faq(faq_id):
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        if request.method == 'DELETE':
            c.execute('DELETE FROM faqs WHERE id = ?', (faq_id,))
            conn.commit()
            conn.close()
            return jsonify({'message': 'FAQ deleted successfully'}), 200
        
        data = request.get_json()
        question = data.get('question')
        answer = data.get('answer')
        category = data.get('category')
        
        if not all([question, answer, category]):
            return jsonify({'error': 'All fields are required'}), 400
        
        c.execute('''
            UPDATE faqs 
            SET question = ?, answer = ?, category = ?, updated_at = datetime('now')
            WHERE id = ?
        ''', (question, answer, category, faq_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'FAQ updated successfully'}), 200
    except Exception as e:
        print("Manage FAQ error:", str(e))
        return jsonify({'error': 'Failed to manage FAQ'}), 500

@app.route('/admin/help_requests')
@admin_required
def admin_help_requests():
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('''
            SELECT hr.*, u.fullname, u.email 
            FROM help_requests hr 
            JOIN users u ON hr.user_id = u.id 
            ORDER BY hr.created_at DESC
        ''')
        help_requests = c.fetchall()
        
        conn.close()
        
        return render_template('admin/help_requests.html', help_requests=help_requests)
    except Exception as e:
        print("Admin help requests error:", str(e))
        return render_template('admin/help_requests.html', help_requests=[])

@app.route('/api/admin/help_request/<int:request_id>', methods=['PUT'])
@admin_required
def respond_to_help_request(request_id):
    try:
        data = request.get_json()
        response = data.get('response')
        status = data.get('status')
        
        if not response or not status:
            return jsonify({'error': 'Response and status are required'}), 400
        
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        c.execute('''
            UPDATE help_requests 
            SET admin_response = ?, status = ?, updated_at = datetime('now')
            WHERE id = ?
        ''', (response, status, request_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Response submitted successfully'}), 200
    except Exception as e:
        print("Respond to help request error:", str(e))
        return jsonify({'error': 'Failed to submit response'}), 500

@app.route('/admin/help')
@admin_required
def admin_help():
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Get FAQs and help requests in one view
        c.execute('SELECT * FROM faqs ORDER BY category, created_at DESC')
        faqs = c.fetchall()
        
        c.execute('''
            SELECT hr.*, u.fullname, u.email 
            FROM help_requests hr 
            JOIN users u ON hr.user_id = u.id 
            ORDER BY hr.created_at DESC
        ''')
        help_requests = c.fetchall()
        
        # Get statistics
        c.execute('SELECT COUNT(*) FROM help_requests WHERE status = "pending"')
        pending_requests = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM help_requests WHERE status = "in_progress"')
        in_progress_requests = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM help_requests WHERE status = "resolved"')
        resolved_requests = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM faqs')
        total_faqs = c.fetchone()[0]
        
        stats = {
            'pending_requests': pending_requests,
            'in_progress_requests': in_progress_requests,
            'resolved_requests': resolved_requests,
            'total_faqs': total_faqs
        }
        
        conn.close()
        
        return render_template('admin/help.html',
                             faqs=faqs,
                             help_requests=help_requests,
                             stats=stats)
    except Exception as e:
        print("Admin help page error:", str(e))
        return render_template('admin/help.html',
                             faqs=[],
                             help_requests=[],
                             stats={
                                 'pending_requests': 0,
                                 'in_progress_requests': 0,
                                 'resolved_requests': 0,
                                 'total_faqs': 0
                             })

def seed_initial_faqs():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    try:
        # Check if FAQs table is empty
        c.execute('SELECT COUNT(*) FROM faqs')
        if c.fetchone()[0] == 0:
            # Initial FAQs data
            faqs = [
                # Account Management
                ('Account Management', 'How do I change my password?', 
                 'Go to your Profile page, click on "Change Password" and follow the instructions.'),
                ('Account Management', 'How do I update my profile information?', 
                 'Visit your Profile page where you can edit your personal information, bio, and profile picture.'),
                ('Account Management', 'What should I do if I forget my password?', 
                 'Click on the "Forgot Password" link on the login page to reset your password using your email.'),
                
                # Email Security
                ('Email Security', 'How secure are my emails?', 
                 'All emails are encrypted and digitally signed. Only the intended recipient can read them.'),
                ('Email Security', 'What happens if someone tries to tamper with my email?', 
                 'Our system uses digital signatures to detect any tampering. Modified emails will be marked as invalid.'),
                ('Email Security', 'How can I verify if an email is authentic?', 
                 'Look for the green verification badge next to authentic emails. Red badges indicate potential tampering.'),
                
                # Attachments
                ('Attachments', 'What types of files can I attach?', 
                 'You can attach PDF, PNG, JPG, JPEG, and DOCX files. Maximum size is 5MB per file.'),
                ('Attachments', 'Why was my attachment blocked?', 
                 'Attachments may be blocked if they exceed 5MB or contain potentially harmful content.'),
                
                # General Usage
                ('General Usage', 'How do I compose a new email?', 
                 'Click the "Compose" button in the navigation menu to create a new email.'),
                ('General Usage', 'Can I recall a sent email?', 
                 'No, once an email is sent it cannot be recalled. Please double-check before sending.')
            ]
            
            c.executemany('''
                INSERT INTO faqs (category, question, answer)
                VALUES (?, ?, ?)
            ''', faqs)
            
            conn.commit()
            print("✅ Added initial FAQs")
    except Exception as e:
        print(f"❌ Error seeding FAQs: {str(e)}")
    finally:
        conn.close()

# --- Admin routes ---
@app.route('/api/admin/help_request/<int:request_id>', methods=['GET'])
@admin_required
def get_help_request(request_id):
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('''
            SELECT hr.*, u.fullname, u.email 
            FROM help_requests hr 
            JOIN users u ON hr.user_id = u.id 
            WHERE hr.id = ?
        ''', (request_id,))
        
        request = c.fetchone()
        conn.close()
        
        if not request:
            return jsonify({'error': 'Help request not found'}), 404
            
        return jsonify(dict(request))
        
    except Exception as e:
        print("Get help request error:", str(e))
        return jsonify({'error': 'Failed to get help request details'}), 500


# --- Run the app ---
if __name__ == '__main__':
    # First create the database and tables
    init_db()
    print("✅ Database initialization completed")
    
    # Then run migrations
    try:
        migrate_db()
        print("✅ Database migration completed successfully")
    except Exception as e:
        print(f"❌ Database migration error: {str(e)}")
    
    # Finally seed initial data
    try:
        seed_initial_faqs()
        print("✅ Initial FAQs seeded successfully")
    except Exception as e:
        print(f"❌ Error seeding FAQs: {str(e)}")
    
    app.run(debug=True)