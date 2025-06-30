import os
import tempfile
import uuid
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_file, session, redirect, url_for
from flask_cors import CORS
from werkzeug.utils import secure_filename
import azure.cognitiveservices.speech as speechsdk
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from google.oauth2 import id_token
import google.auth.transport.requests
import requests
import io
from pydub import AudioSegment
from docx import Document
import json
from functools import wraps
import stripe
import sqlite3
from contextlib import contextmanager

# Try to import PostgreSQL support, fall back to SQLite if not available
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False
    print("psycopg2 not available, using SQLite for database operations")

# Disable OAuth2 HTTPS requirement for local development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=['http://localhost:5000'])
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production-seriously')

# Session configuration
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Application Configuration
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'wav', 'mp3', 'aac', 'm4a', 'flac', 'ogg'}

# Environment variables
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
AZURE_SPEECH_KEY = os.environ.get('AZURE_SPEECH_KEY')
AZURE_SPEECH_REGION = os.environ.get('AZURE_SPEECH_REGION')
AZURE_SPEECH_ENDPOINT = os.environ.get('AZURE_SPEECH_ENDPOINT')

# Stripe Configuration
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')
SUBSCRIPTION_PRICE_ID = os.environ.get('STRIPE_PRICE_ID')  # Your £5/month price ID

# Database setup
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///app.db')

def init_db():
    """Initialize the database with required tables."""
    if DATABASE_URL.startswith('postgresql://') and POSTGRES_AVAILABLE:
        # PostgreSQL initialization
        try:
            conn = psycopg2.connect(DATABASE_URL)
            with conn.cursor() as cur:
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        google_id TEXT UNIQUE NOT NULL,
                        email TEXT NOT NULL,
                        name TEXT NOT NULL,
                        picture TEXT,
                        stripe_customer_id TEXT,
                        subscription_status TEXT DEFAULT 'inactive',
                        subscription_id TEXT,
                        subscription_end_date TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS transcriptions (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL,
                        filename TEXT NOT NULL,
                        transcript TEXT NOT NULL,
                        word_count INTEGER,
                        confidence REAL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')
            conn.commit()
            conn.close()
            print("PostgreSQL database initialized successfully")
        except Exception as e:
            print(f"PostgreSQL initialization failed: {e}")
    else:
        # SQLite fallback
        database_file = DATABASE_URL.replace('sqlite:///', '') if DATABASE_URL.startswith('sqlite://') else 'app.db'
        with sqlite3.connect(database_file) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    google_id TEXT UNIQUE NOT NULL,
                    email TEXT NOT NULL,
                    name TEXT NOT NULL,
                    picture TEXT,
                    stripe_customer_id TEXT,
                    subscription_status TEXT DEFAULT 'inactive',
                    subscription_id TEXT,
                    subscription_end_date DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS transcriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    filename TEXT NOT NULL,
                    transcript TEXT NOT NULL,
                    word_count INTEGER,
                    confidence REAL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
        print("SQLite database initialized successfully")

@contextmanager
def get_db_connection():
    """Context manager for database connections."""
    if DATABASE_URL.startswith('postgresql://') and POSTGRES_AVAILABLE:
        # PostgreSQL connection
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        try:
            yield conn
        finally:
            conn.close()
    else:
        # SQLite fallback
        database_file = DATABASE_URL.replace('sqlite:///', '') if DATABASE_URL.startswith('sqlite://') else 'app.db'
        conn = sqlite3.connect(database_file)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

def execute_query(conn, query, params=None, fetch=False):
    """Execute query with proper syntax for PostgreSQL or SQLite."""
    if DATABASE_URL.startswith('postgresql://') and POSTGRES_AVAILABLE:
        # PostgreSQL uses %s placeholders
        pg_query = query.replace('?', '%s')
        with conn.cursor() as cur:
            cur.execute(pg_query, params or ())
            if fetch == 'one':
                return cur.fetchone()
            elif fetch == 'all':
                return cur.fetchall()
            conn.commit()
    else:
        # SQLite uses ? placeholders
        if fetch == 'one':
            return conn.execute(query, params or ()).fetchone()
        elif fetch == 'all':
            return conn.execute(query, params or ()).fetchall()
        else:
            conn.execute(query, params or ())
            conn.commit()

def get_or_create_user(google_user_info):
    """Get or create user in database."""
    with get_db_connection() as conn:
        user = execute_query(
            conn,
            'SELECT * FROM users WHERE google_id = ?',
            (google_user_info['id'],),
            fetch='one'
        )
        
        if user:
            # Update user info
            execute_query(conn, '''
                UPDATE users 
                SET email = ?, name = ?, picture = ?, updated_at = CURRENT_TIMESTAMP
                WHERE google_id = ?
            ''', (google_user_info['email'], google_user_info['name'], 
                  google_user_info.get('picture', ''), google_user_info['id']))
            return dict(user)
        else:
            # Create new user
            if DATABASE_URL.startswith('postgresql://') and POSTGRES_AVAILABLE:
                with conn.cursor() as cur:
                    cur.execute('''
                        INSERT INTO users (google_id, email, name, picture)
                        VALUES (%s, %s, %s, %s)
                        RETURNING id
                    ''', (google_user_info['id'], google_user_info['email'], 
                          google_user_info['name'], google_user_info.get('picture', '')))
                    user_id = cur.fetchone()['id']
                    conn.commit()
            else:
                cursor = conn.execute('''
                    INSERT INTO users (google_id, email, name, picture)
                    VALUES (?, ?, ?, ?)
                ''', (google_user_info['id'], google_user_info['email'], 
                      google_user_info['name'], google_user_info.get('picture', '')))
                conn.commit()
                user_id = cursor.lastrowid
            
            return {
                'id': user_id,
                'google_id': google_user_info['id'],
                'email': google_user_info['email'],
                'name': google_user_info['name'],
                'picture': google_user_info.get('picture', ''),
                'stripe_customer_id': None,
                'subscription_status': 'inactive'
            }

def update_user_subscription(user_id, stripe_customer_id, subscription_status, subscription_id=None, end_date=None):
    """Update user subscription information."""
    with get_db_connection() as conn:
        # Ensure end_date is a datetime object if not None, for consistent database storage
        if isinstance(end_date, str):
            # This might happen if a string was passed from a previous state or a different source
            try:
                end_date = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            except ValueError:
                print(f"Warning: Could not parse end_date string '{end_date}'. Storing as None.")
                end_date = None
        
        execute_query(conn, '''
            UPDATE users 
            SET stripe_customer_id = ?, subscription_status = ?, 
                subscription_id = ?, subscription_end_date = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (stripe_customer_id, subscription_status, subscription_id, end_date, user_id)) # Pass datetime object directly

def is_subscription_active(user_id):
    """Check if user has an active subscription."""
    with get_db_connection() as conn:
        user = execute_query(conn,
            'SELECT subscription_status, subscription_end_date FROM users WHERE id = ?',
            (user_id,),
            fetch='one'
        )
        
        if not user:
            return False
            
        if user['subscription_status'] == 'active':
            # Check if subscription hasn't expired
            if user['subscription_end_date']:
                if isinstance(user['subscription_end_date'], str):
                    end_date = datetime.fromisoformat(user['subscription_end_date'].replace('Z', '+00:00'))
                else:
                    end_date = user['subscription_end_date']
                return datetime.now() < end_date
            return True # If no end_date, assume perpetual active (unlikely for subscriptions but defensively coded)
            
        return False

# OAuth and Google setup
client_config = None
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    client_config = {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": ["http://localhost:5000/auth/callback"]
        }
    }

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Azure Speech setup
speech_config = None
try:
    if AZURE_SPEECH_KEY and AZURE_SPEECH_REGION:
        speech_config = speechsdk.SpeechConfig(subscription=AZURE_SPEECH_KEY, region=AZURE_SPEECH_REGION)
        if AZURE_SPEECH_ENDPOINT:
            speech_config.endpoint_id = AZURE_SPEECH_ENDPOINT
        speech_config.speech_recognition_language = "en-US"
        speech_config.output_format = speechsdk.OutputFormat.Detailed
        print("Azure Speech client initialized successfully.")
    else:
        print("Warning: AZURE_SPEECH_KEY or AZURE_SPEECH_REGION not set.")
except Exception as e:
    print(f"Warning: Azure Speech client initialization failed: {e}")
    speech_config = None

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({"error": "Authentication required", "redirect": "/auth/login"}), 401
        return f(*args, **kwargs)
    return decorated_function

def subscription_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({"error": "Authentication required", "redirect": "/auth/login"}), 401
        
        if not is_subscription_active(session['user_db']['id']):
            return jsonify({
                "error": "Active subscription required", 
                "redirect": "/subscription",
                "subscription_status": "inactive"
            }), 402  # Payment Required
        return f(*args, **kwargs)
    return decorated_function

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def convert_to_wav(input_path, output_path):
    try:
        audio = AudioSegment.from_file(input_path)
        audio = audio.set_channels(1).set_frame_rate(16000).set_sample_width(2)
        audio.export(output_path, format="wav")
    except Exception as e:
        print(f"Audio conversion error: {e}")
        return False
    return True

def transcribe_audio(audio_path):
    if not speech_config:
        return {"error": "Azure Speech client not initialized."}
    
    try:
        audio_config = speechsdk.audio.AudioConfig(filename=audio_path)
        speech_recognizer = speechsdk.SpeechRecognizer(speech_config=speech_config, audio_config=audio_config)
        
        done = False
        results = []
        
        def stop_cb(evt):
            nonlocal done
            done = True
        
        def recognized_cb(evt):
            if evt.result.reason == speechsdk.ResultReason.RecognizedSpeech:
                results.append({
                    'text': evt.result.text,
                    'confidence': evt.result.properties.get(speechsdk.PropertyId.SpeechServiceResponse_JsonResult, '{}')
                })
        
        speech_recognizer.recognized.connect(recognized_cb)
        speech_recognizer.session_stopped.connect(stop_cb)
        speech_recognizer.canceled.connect(stop_cb)
        
        speech_recognizer.start_continuous_recognition()
        
        import time
        timeout = 300
        start_time = time.time()
        
        while not done and (time.time() - start_time) < timeout:
            time.sleep(0.5)
        
        speech_recognizer.stop_continuous_recognition()
        
        if not results:
            return {"error": "No speech recognized in the audio file."}
        
        full_transcript = " ".join([result['text'] for result in results])
        word_count = len(full_transcript.split()) if full_transcript else 0
        
        return {
            "transcript": full_transcript,
            "confidence": 0.85,
            "word_count": word_count
        }
        
    except Exception as e:
        return {"error": f"Transcription failed: {str(e)}"}

def create_docx(transcript, filename="transcript"):
    doc = Document()
    header = doc.sections[0].header
    header_para = header.paragraphs[0]
    header_para.text = f"Audio Transcript - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    
    title = doc.add_heading('Audio Transcription', 0)
    doc.add_paragraph(transcript)
    
    footer = doc.sections[0].footer
    footer_para = footer.paragraphs[0]
    footer_para.text = f"Word count: {len(transcript.split())} words"
    
    temp_path = os.path.join(tempfile.gettempdir(), f"{filename}_{uuid.uuid4().hex}.docx")
    doc.save(temp_path)
    return temp_path

# Routes
@app.route('/')
def index():
    return send_file('index.html')

@app.route('/api/status')
def api_status():
    user_status = {}
    if 'user' in session and 'user_db' in session:
        user_status = {
            "authenticated": True,
            "user": session['user']['name'],
            "subscription_active": is_subscription_active(session['user_db']['id']),
            "subscription_status": session['user_db']['subscription_status']
        }
    else:
        user_status = {"authenticated": False}
    
    return jsonify({
        "message": "Speech-to-Text API is running",
        **user_status
    })

@app.route('/debug/user-info')
@login_required
def debug_user_info():
    user_db = session['user_db']
    
    # Get detailed user info from database
    with get_db_connection() as conn:
        user = execute_query(conn,
            'SELECT * FROM users WHERE id = ?',
            (user_db['id'],),
            fetch='one'
        )
        
        if user:
            user_dict = dict(user)
            # Don't expose sensitive data in debug
            return jsonify({
                "user_id": user_dict['id'],
                "email": user_dict['email'],
                "stripe_customer_id": user_dict['stripe_customer_id'],
                "subscription_status": user_dict['subscription_status'],
                "subscription_id": user_dict['subscription_id'],
                "subscription_end_date": str(user_dict['subscription_end_date']) if user_dict['subscription_end_date'] else None,
                "created_at": str(user_dict['created_at']),
                "updated_at": str(user_dict['updated_at'])
            })
        else:
            return jsonify({"error": "User not found in database"})

# Authentication routes
@app.route('/auth/login')
def login():
    if not client_config:
        return jsonify({"error": "Google OAuth not configured"}), 500
    
    try:
        google_scopes = [
            'openid',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile'
        ]
        
        flow = Flow.from_client_config(client_config, scopes=google_scopes)
        flow.redirect_uri = url_for('auth_callback', _external=True)
        
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        
        session['state'] = state
        session['oauth_scopes'] = google_scopes
        
        return jsonify({"auth_url": authorization_url})
    
    except Exception as e:
        return jsonify({"error": f"Login failed: {str(e)}"}), 500

@app.route('/auth/callback')
def auth_callback():
    if not client_config:
        return jsonify({"error": "Google OAuth not configured"}), 500
    
    try:
        if 'state' not in session or request.args.get('state') != session['state']:
            return redirect('/?auth=error')
        
        flow = Flow.from_client_config(
            client_config,
            scopes=[
                'openid',
                'https://www.googleapis.com/auth/userinfo.email',
                'https://www.googleapis.com/auth/userinfo.profile'
            ],
            state=session['state']
        )
        flow.redirect_uri = url_for('auth_callback', _external=True)
        
        flow.fetch_token(authorization_response=request.url)
        
        credentials = flow.credentials
        request_session = google.auth.transport.requests.Request()
        
        id_info = id_token.verify_oauth2_token(
            credentials.id_token,
            request_session,
            GOOGLE_CLIENT_ID
        )
        
        # Store Google user info in session
        session['user'] = {
            'id': id_info['sub'],
            'email': id_info['email'],
            'name': id_info['name'],
            'picture': id_info.get('picture', ''),
            'verified_email': id_info.get('email_verified', False)
        }
        
        # Get or create user in database
        user_db = get_or_create_user(session['user'])
        session['user_db'] = user_db
        
        session.pop('state', None)
        session.pop('oauth_scopes', None)
        
        return redirect('/?auth=success')
        
    except Exception as e:
        print(f"Authentication error: {e}")
        session.pop('state', None)
        session.pop('oauth_scopes', None)
        return redirect('/?auth=error')

@app.route('/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"})

@app.route('/auth/user')
def get_user():
    if 'user' in session and 'user_db' in session:
        return jsonify({
            "authenticated": True,
            "user": session['user'],
            "subscription_active": is_subscription_active(session['user_db']['id']),
            "subscription_status": session['user_db']['subscription_status']
        })
    else:
        return jsonify({"authenticated": False, "user": None})

# Subscription routes
@app.route('/api/subscription/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    try:
        user_db = session['user_db']
        
        # Create or get Stripe customer
        if not user_db['stripe_customer_id']:
            customer = stripe.Customer.create(
                email=session['user']['email'],
                name=session['user']['name']
            )
            customer_id = customer.id
            
            # Update user with Stripe customer ID
            update_user_subscription(user_db['id'], customer_id, user_db['subscription_status'])
            session['user_db']['stripe_customer_id'] = customer_id
        else:
            customer_id = user_db['stripe_customer_id']
        
        # Create checkout session
        checkout_session = stripe.checkout.Session.create(
            customer=customer_id,
            payment_method_types=['card'],
            line_items=[{
                'price': SUBSCRIPTION_PRICE_ID,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=url_for('subscription_success', _external=True),
            cancel_url=url_for('subscription_cancel', _external=True),
            metadata={'user_id': str(user_db['id'])}
        )
        
        return jsonify({'checkout_url': checkout_session.url})
        
    except Exception as e:
        print(f"Checkout session creation failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/subscription/success')
def subscription_success():
    return redirect('/?subscription=success')

@app.route('/subscription/cancel')
def subscription_cancel():
    return redirect('/?subscription=cancelled')

@app.route('/api/subscription/portal', methods=['POST'])
@login_required
def customer_portal():
    try:
        user_db = session['user_db']
        
        if not user_db['stripe_customer_id']:
            return jsonify({'error': 'No Stripe customer found'}), 400
        
        portal_session = stripe.billing_portal.Session.create(
            customer=user_db['stripe_customer_id'],
            return_url=url_for('index', _external=True)
        )
        
        return jsonify({'portal_url': portal_session.url})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/subscription/status')
@login_required
def subscription_status():
    user_db = session['user_db']
    is_active = is_subscription_active(user_db['id'])
    
    return jsonify({
        'subscription_active': is_active,
        'subscription_status': user_db['subscription_status'],
        'stripe_customer_id': user_db['stripe_customer_id'] is not None
    })

# Webhook for Stripe events
@app.route('/stripe/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        # Verify webhook signature
        if STRIPE_WEBHOOK_SECRET:
            event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
        else:
            # For testing without webhook secret
            event = json.loads(payload)
            print("Warning: Processing webhook without signature verification (STRIPE_WEBHOOK_SECRET not set).")
        
        print(f"Webhook received: {event['type']} (Event ID: {event['id']})")
        
    except ValueError as e:
        print(f"Invalid payload: {e}")
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError as e:
        print(f"Invalid signature: {e}")
        return 'Invalid signature', 400
    
    try:
        # Handle subscription events
        if event['type'] == 'customer.subscription.created':
            subscription = event['data']['object']
            handle_subscription_created(subscription)
        elif event['type'] == 'customer.subscription.updated':
            subscription = event['data']['object']
            handle_subscription_updated(subscription)
        elif event['type'] == 'customer.subscription.deleted':
            subscription = event['data']['object']
            handle_subscription_deleted(subscription)
        elif event['type'] == 'invoice.payment_succeeded':
            invoice = event['data']['object']
            handle_payment_succeeded(invoice)
        elif event['type'] == 'invoice.payment_failed':
            invoice = event['data']['object']
            handle_payment_failed(invoice)
        else:
            print(f"Unhandled event type: {event['type']}")
        
        return 'Success', 200
        
    except Exception as e:
        print(f"Webhook processing error for event {event.get('id', 'N/A')}: {e}")
        import traceback
        traceback.print_exc()
        return 'Webhook processing failed', 500

def handle_subscription_created(subscription):
    try:
        customer_id = subscription['customer']
        subscription_id = subscription['id']
        status = subscription['status']
        
        print(f"handle_subscription_created: Processing subscription {subscription_id} for customer {customer_id} with status {status}")
        
        with get_db_connection() as conn:
            user = execute_query(conn,
                'SELECT id FROM users WHERE stripe_customer_id = ?',
                (customer_id,),
                fetch='one'
            )
            
            if user:
                user_id = user['id']
                # Convert Unix timestamp to datetime object
                # Stripe's current_period_end is a Unix timestamp (integer)
                end_date = datetime.fromtimestamp(subscription['current_period_end'])
                
                print(f"handle_subscription_created: Found user {user_id}. Updating subscription to status='{status}', id='{subscription_id}', end_date='{end_date}'")
                
                execute_query(conn, '''
                    UPDATE users 
                    SET subscription_status = ?, subscription_id = ?, subscription_end_date = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE stripe_customer_id = ?
                ''', (status, subscription_id, end_date, customer_id)) # FIX: Pass datetime object directly
                
                print(f"handle_subscription_created: Successfully updated subscription for user {user_id}")
            else:
                print(f"handle_subscription_created: No user found in DB for Stripe customer ID: {customer_id}. This subscription will not be recorded.")
                # You might want to add logic here to create a user or link to an existing one by email
                # if this scenario is expected (e.g., customer created in Stripe first).
                
    except Exception as e:
        print(f"Error in handle_subscription_created for subscription {subscription.get('id', 'N/A')}: {e}")
        import traceback
        traceback.print_exc()
        raise # Re-raise to ensure the 500 is sent back to Stripe for visibility.

def handle_subscription_updated(subscription):
    # Same logic as created, but adding a specific print for clarity
    print(f"handle_subscription_updated: Processing subscription update for {subscription.get('id', 'N/A')}")
    handle_subscription_created(subscription)

def handle_subscription_deleted(subscription):
    try:
        customer_id = subscription['customer']
        
        print(f"handle_subscription_deleted: Processing subscription deletion for customer {customer_id}")
        
        with get_db_connection() as conn:
            execute_query(conn, '''
                UPDATE users 
                SET subscription_status = 'canceled', subscription_id = NULL, subscription_end_date = NULL, updated_at = CURRENT_TIMESTAMP
                WHERE stripe_customer_id = ?
            ''', (customer_id,))
            print(f"handle_subscription_deleted: Canceled subscription for customer {customer_id}")
            
    except Exception as e:
        print(f"Error in handle_subscription_deleted: {e}")
        raise

def handle_payment_succeeded(invoice):
    try:
        if invoice.get('subscription'):
            # Fetch the subscription to get updated info
            subscription = stripe.Subscription.retrieve(invoice['subscription'])
            print(f"handle_payment_succeeded: Payment succeeded for subscription {invoice['subscription']}. Calling handle_subscription_created.")
            handle_subscription_created(subscription)
        else:
            print(f"handle_payment_succeeded: Payment succeeded for non-subscription invoice {invoice.get('id', 'N/A')}")
            
    except Exception as e:
        print(f"Error in handle_payment_succeeded: {e}")
        raise

def handle_payment_failed(invoice):
    try:
        customer_id = invoice['customer']
        
        print(f"handle_payment_failed: Payment failed for customer {customer_id}")
        
        with get_db_connection() as conn:
            execute_query(conn, '''
                UPDATE users 
                SET subscription_status = 'past_due', updated_at = CURRENT_TIMESTAMP
                WHERE stripe_customer_id = ?
            ''', (customer_id,))
            print(f"handle_payment_failed: Updated user status to 'past_due' for customer {customer_id}")
            
    except Exception as e:
        print(f"Error in handle_payment_failed: {e}")
        raise

# Protected transcription routes
@app.route('/upload', methods=['POST'])
@subscription_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    if not allowed_file(file.filename):
        return jsonify({"error": f"File type not supported. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"}), 400
    
    try:
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        file.save(file_path)
        
        wav_path = file_path
        if not filename.lower().endswith('.wav'):
            wav_path = os.path.join(UPLOAD_FOLDER, f"{unique_filename}.wav")
            if not convert_to_wav(file_path, wav_path):
                os.remove(file_path)
                return jsonify({"error": "Failed to convert audio file to WAV."}), 500
        
        result = transcribe_audio(wav_path)
        
        # Clean up files
        try:
            os.remove(file_path)
            if wav_path != file_path:
                os.remove(wav_path)
        except Exception:
            pass
        
        if "error" in result:
            return jsonify(result), 500
        
        # Save transcription to database
        user_db = session['user_db']
        with get_db_connection() as conn:
            execute_query(conn, '''
                INSERT INTO transcriptions (user_id, filename, transcript, word_count, confidence)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_db['id'], filename, result['transcript'], result['word_count'], result['confidence']))
        
        return jsonify({
            "success": True,
            "transcript": result["transcript"],
            "confidence": result["confidence"],
            "word_count": result["word_count"],
            "filename": filename,
            "user": session['user']['name']
        })
    
    except Exception as e:
        print(f"Upload failed: {e}")
        return jsonify({"error": f"Processing failed: {str(e)}"}), 500

@app.route('/download', methods=['POST'])
@subscription_required
def download_transcript():
    data = request.get_json()
    if not data or 'transcript' not in data:
        return jsonify({"error": "No transcript provided"}), 400
    
    try:
        transcript = data['transcript']
        filename = data.get('filename', 'transcript')
        
        if '.' in filename:
            filename = filename.rsplit('.', 1)[0]
        
        docx_path = create_docx(transcript, filename)
        
        return send_file(
            docx_path,
            as_attachment=True,
            download_name=f"{filename}_transcript.docx",
            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        )
    
    except Exception as e:
        return jsonify({"error": f"Document creation failed: {str(e)}"}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "database_type": "PostgreSQL" if (DATABASE_URL.startswith('postgresql://') and POSTGRES_AVAILABLE) else "SQLite",
        "azure_speech_initialized": speech_config is not None,
        "google_oauth_configured": client_config is not None,
        "stripe_configured": stripe.api_key is not None,
        "authenticated_session_active": 'user' in session,
        "timestamp": datetime.now().isoformat()
    })

# Initialize database on startup
init_db()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
