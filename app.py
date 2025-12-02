import os
import json 
import random
import string
import datetime
import firebase_admin
from threading import Thread 
from dotenv import load_dotenv
from firebase_admin import credentials, auth, firestore, storage
from flask import Flask, render_template, request, redirect, url_for, session, make_response, jsonify
from flask_mail import Mail, Message
import google.auth.transport.requests
import google.generativeai as genai

# Load the hidden variables
load_dotenv()

# Get the key safely
GEMINI_KEY = os.getenv('GEMINI_API_KEY')

# Configure AI
genai.configure(api_key=GEMINI_KEY)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'YOUR_VERY_STRONG_SECRET_KEY_FOR_SESSIONS' 

# --- MAILTRAP CONFIG ---
app.config['MAIL_SERVER']='sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = '1bad53dbfb1c0a'
app.config['MAIL_PASSWORD'] = '49b4b2fb3b69fe'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

# --- AI CONFIGURATION ---
GENAI_API_KEY = "AIzaSyCrD-l6d3WBIo29a2GoUzaWmZMqUJL5w2I"
genai.configure(api_key=GENAI_API_KEY)
model = genai.GenerativeModel('gemini-2.5-flash')

mail = Mail(app) 

KEY_FILE_NAME = 'key.json' 
STORAGE_BUCKET = "unitrade-839f0.firebasestorage.app" 
ADMIN_EMAILS = ["test@unitrade.com"]

# --- DATA LISTS ---
FACULTIES = [
    "Faculty of Quranic and Sunnah Studies (FPQS)", "Faculty of Leadership and Management (FKP)",
    "Faculty of Syariah and Law (FSU)", "Faculty of Economics and Muamalat (FEM)",
    "Faculty of Science and Technology (FST)", "Faculty of Medicine and Health Sciences (FPSK)",
    "Faculty of Major Language Studies (FPBU)", "Faculty of Dentistry (FPg)",
    "Faculty of Engineering and Built Environment (FKAB)", "Tamhidi Centre", "STAFF"
]

CATEGORIES = ["Textbooks", "Electronics", "Clothing", "Food", "Furniture", "Stationery", "Others"]
CONDITIONS = ["Brand New", "Like New", "Lightly Used", "Well Used", "Heavily Used"]

db = None
bucket = None
cred = None

if os.path.exists(KEY_FILE_NAME):
    cred = credentials.Certificate(KEY_FILE_NAME)
elif os.environ.get('FIREBASE_CREDENTIALS'):
    creds_json = json.loads(os.environ.get('FIREBASE_CREDENTIALS'))
    cred = credentials.Certificate(creds_json)

if cred:
    if not firebase_admin._apps:
        firebase_admin.initialize_app(cred, {'storageBucket': STORAGE_BUCKET})
    db = firestore.client()
    bucket = storage.bucket()
else:
    print("WARNING: No credentials found.")

# --- HELPER FUNCTIONS ---

# NEW: Async Email Function
def send_async_email(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
            print("Email sent successfully!")
        except Exception as e:
            print(f"Failed to send email: {e}")

def login_required(f):
    def wrap(*args, **kwargs):
        if 'logged_in' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

def seller_required(f):
    def wrap(*args, **kwargs):
        if 'logged_in' not in session: return redirect(url_for('login'))
        user_doc = db.collection('users').document(session['uid']).get()
        if user_doc.exists:
            status = user_doc.to_dict().get('seller_status', 'none')
            if status != 'approved': return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

def get_chat_room_id(uid1, uid2): return '_'.join(sorted([uid1, uid2]))

# --- ROUTES ---

@app.route('/')
def index():
    if session.get('logged_in'): return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET'])
def login(): return render_template('login.html')

@app.route('/register', methods=['GET'])
def register(): return render_template('signup.html', faculties=FACULTIES)

@app.route('/dashboard')
@login_required 
def dashboard():
    global db
    user_email = session.get('user_email', 'User')
    current_uid = session.get('uid')
    is_admin = user_email in ADMIN_EMAILS 
    
    search_query = request.args.get('q', '').lower()
    category_filter = request.args.get('category', 'All')
    
    user_doc = db.collection('users').document(current_uid).get()
    seller_status = user_doc.to_dict().get('seller_status', 'none') if user_doc.exists else 'none'

    products = []
    services = []
    orders = [] 
    purchases = []

    try:
        products_ref = db.collection('products').order_by('created_at', direction=firestore.Query.DESCENDING).stream()
        for doc in products_ref:
            p = doc.to_dict()
            p['id'] = doc.id
            if p.get('status') != 'sold': 
                matches_search = not search_query or (search_query in p.get('name', '').lower() or search_query in p.get('description', '').lower())
                matches_cat = category_filter == 'All' or p.get('category') == category_filter
                if matches_search and matches_cat: products.append(p)
        products = products[:20] 

        services_ref = db.collection('services').order_by('created_at', direction=firestore.Query.DESCENDING).stream()
        for doc in services_ref:
            s = doc.to_dict()
            s['id'] = doc.id
            if not search_query or (search_query in s.get('service_type', '').lower() or search_query in s.get('description', '').lower()):
                services.append(s)

        orders_ref = db.collection('transactions').where('seller_uid', '==', current_uid).where('status', '==', 'pending_approval').stream()
        for doc in orders_ref:
            o = doc.to_dict()
            o['id'] = doc.id
            orders.append(o)

        purchases_ref = db.collection('transactions').where('buyer_uid', '==', current_uid).stream()
        for doc in purchases_ref:
            p = doc.to_dict()
            p['id'] = doc.id
            purchases.append(p)
            
    except Exception as e: print(f"Error: {e}")

    return render_template('dashboard.html', 
                           user_email=user_email, products=products, services=services, 
                           orders=orders, purchases=purchases, is_admin=is_admin,
                           categories=CATEGORIES, current_category=category_filter,
                           seller_status=seller_status)

@app.route('/leaderboard')
def leaderboard():
    top_sellers = []
    try:
        users_ref = db.collection('users').order_by('sold_count', direction=firestore.Query.DESCENDING).limit(10).stream()
        for doc in users_ref:
            u = doc.to_dict()
            if u.get('sold_count', 0) > 0:
                u['uid'] = doc.id 
                top_sellers.append(u)
    except Exception: pass
    return render_template('leaderboard.html', top_sellers=top_sellers)

@app.route('/apply_seller', methods=['GET'])
@login_required
def apply_seller(): return render_template('apply_seller.html')

@app.route('/sell', methods=['GET'])
@login_required 
@seller_required 
def sell(): return render_template('sell.html', categories=CATEGORIES, conditions=CONDITIONS)

@app.route('/offer_service', methods=['GET'])
@login_required 
@seller_required 
def offer_service(): return render_template('services.html')

@app.route('/inbox')
@login_required
def inbox():
    current_uid = session.get('uid')
    chat_list = []
    try:
        chats_ref = db.collection('chats').where('participants', 'array_contains', current_uid).stream()
        for doc in chats_ref:
            data = doc.to_dict()
            other_uid = next((uid for uid in data['participants'] if uid != current_uid), None)
            if other_uid:
                chat_list.append({'other_uid': other_uid, 'other_email': data['emails'].get(other_uid, 'User'), 'last_message': data['last_message']})
    except Exception: pass
    return render_template('inbox.html', chats=chat_list)

@app.route('/profile')
@app.route('/profile/<target_uid>')
@login_required 
def profile(target_uid=None):
    current_uid = session.get('uid')
    view_uid = target_uid if target_uid else current_uid
    is_own_profile = (view_uid == current_uid)
    user_products = []
    user_services = []
    user_info = {}
    reviews = []
    try:
        user_doc = db.collection('users').document(view_uid).get()
        if user_doc.exists: user_info = user_doc.to_dict()
        products_ref = db.collection('products').where('seller_uid', '==', view_uid).stream()
        for doc in products_ref: user_products.append(doc.to_dict() | {'id': doc.id})
        services_ref = db.collection('services').where('provider_uid', '==', view_uid).stream()
        for doc in services_ref: user_services.append(doc.to_dict() | {'id': doc.id})
        reviews_ref = db.collection('users').document(view_uid).collection('reviews').stream()
        for doc in reviews_ref: reviews.append(doc.to_dict())
    except Exception: pass
    return render_template('profile.html', products=user_products, services=user_services, user=user_info, is_own_profile=is_own_profile, reviews=reviews, view_uid=view_uid)

@app.route('/settings')
@login_required 
def settings():
    user_info = {}
    try:
        user_doc = db.collection('users').document(session['uid']).get()
        if user_doc.exists: user_info = user_doc.to_dict()
    except Exception: pass
    return render_template('settings.html', user=user_info, faculties=FACULTIES)

@app.route('/chat/<seller_uid>', methods=['GET'])
@login_required
def chat(seller_uid):
    current_uid = session.get('uid')
    current_email = session.get('user_email')
    room_id = get_chat_room_id(current_uid, seller_uid)
    item_id = request.args.get('item_id')
    item_context = None
    try:
        opponent_doc = db.collection('users').document(seller_uid).get()
        opponent_email = opponent_doc.to_dict().get('email', 'Seller')
        if item_id:
            item_doc = db.collection('products').document(item_id).get()
            if not item_doc.exists: item_doc = db.collection('services').document(item_id).get()
            if item_doc.exists: item_context = item_doc.to_dict()
    except Exception: opponent_email = 'Unknown'
    return render_template('chat.html', room_id=room_id, opponent_email=opponent_email, seller_uid=seller_uid, current_uid=current_uid, current_email=current_email, item_context=item_context)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login')) 

@app.route('/admin')
@login_required
def admin_dashboard():
    if session.get('user_email') not in ADMIN_EMAILS: return "Access Denied", 403
    reports = []
    applications = []
    try:
        reports_ref = db.collection('reports').order_by('timestamp', direction=firestore.Query.DESCENDING).stream()
        for doc in reports_ref: reports.append(doc.to_dict() | {'id': doc.id})
        apps_ref = db.collection('seller_applications').where('status', '==', 'pending').stream()
        for doc in apps_ref: applications.append(doc.to_dict() | {'id': doc.id})
    except Exception: pass
    return render_template('admin.html', reports=reports, applications=applications)

# --- API ROUTES ---

@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.get_json()
    try:
        try: user = auth.create_user(email=data['email'], password=data['password']); uid = user.uid
        except: user = auth.get_user_by_email(data['email']); uid = user.uid
        db.collection('users').document(uid).set({
            'email': data['email'], 'full_name': data.get('fullName'), 'phone_number': data.get('phoneNumber'), 
            'faculty': data.get('faculty'), 'seller_status': 'none', 'sold_count': 0, 'created_at': firestore.SERVER_TIMESTAMP
        }, merge=True)
        return jsonify({'success': True, 'message': 'Account created.'})
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    try:
        decoded_token = auth.verify_id_token(data['idToken'], clock_skew_seconds=60)
        uid = decoded_token['uid']; email = data['email']
        otp = ''.join(random.choices(string.digits, k=6))
        session['temp_uid'] = uid; session['temp_email'] = email; session['mfa_otp'] = otp
        
        # THREADED EMAIL SENDING (FIXES TIMEOUT)
        msg = Message('UniTrade Login Code', sender='security@unitrade.com', recipients=[email])
        msg.body = f"Your code: {otp}"
        Thread(target=send_async_email, args=(app, msg)).start() # <--- This line fixes the lag!
        
        return jsonify({'success': True, 'mfa_required': True})
    except Exception as e: print(f"Login Error: {e}"); return jsonify({'success': False, 'message': 'Login failed.'}), 401

@app.route('/api/verify_mfa', methods=['POST'])
def api_verify_mfa():
    data = request.get_json()
    if 'mfa_otp' in session and session['mfa_otp'] == data.get('otp'):
        session['logged_in'] = True; session['uid'] = session['temp_uid']; session['user_email'] = session['temp_email']
        session.pop('temp_uid', None); session.pop('temp_email', None); session.pop('mfa_otp', None)
        return jsonify({'success': True, 'redirect_url': url_for('dashboard')})
    return jsonify({'success': False, 'message': 'Invalid Code'}), 400

@app.route('/api/sell', methods=['POST'])
def api_sell():
    data = request.get_json()
    try:
        decoded_token = auth.verify_id_token(data['idToken'])
        user_uid = decoded_token['uid']
        user_doc = db.collection('users').document(user_uid).get()
        user_name = user_doc.to_dict().get('full_name', 'Student') if user_doc.exists else 'Student'
        db.collection('products').add({
            'seller_uid': user_uid, 'seller_email': decoded_token.get('email'), 'seller_name': user_name,
            'name': data.get('name'), 'description': data.get('description'), 'price': float(data.get('price')),
            'category': data.get('category'), 'condition': data.get('condition'),
            'image_url': data.get('image_url'), 'status': 'available', 'created_at': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'success': True, 'redirect_url': url_for('dashboard')})
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/offer_service', methods=['POST'])
def api_offer_service():
    data = request.get_json()
    try:
        decoded_token = auth.verify_id_token(data['idToken'])
        user_uid = decoded_token['uid']
        user_doc = db.collection('users').document(user_uid).get()
        user_name = user_doc.to_dict().get('full_name', 'Provider') if user_doc.exists else 'Provider'
        db.collection('services').add({
            'provider_uid': user_uid, 'provider_email': decoded_token.get('email'), 'provider_name': user_name,
            'service_type': data.get('service_type'), 'description': data.get('description'), 'price': float(data.get('price')),
            'image_url': data.get('image_url'), 'is_available': True, 'created_at': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'success': True, 'redirect_url': url_for('dashboard')})
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/buy_request', methods=['POST'])
@login_required
def api_buy_request():
    data = request.get_json()
    try:
        db.collection('transactions').add({
            'buyer_uid': session['uid'], 'buyer_email': session['user_email'],
            'seller_uid': data['seller_uid'], 'item_id': data['item_id'], 'item_name': data['item_name'],
            'payment_method': data['payment_method'], 'proof_image': data.get('proof_image'),
            'status': 'pending_approval', 'created_at': firestore.SERVER_TIMESTAMP
        })
        room_id = get_chat_room_id(session['uid'], data['seller_uid'])
        msg_text = f"📢 Buy Request for '{data['item_name']}'"
        db.collection('chats').doc(room_id).collection('messages').add({'text': msg_text, 'timestamp': firestore.SERVER_TIMESTAMP, 'sender_uid': session['uid']})
        db.collection('chats').doc(room_id).set({'participants': [session['uid'], data['seller_uid']], 'last_message': "New Buy Request", 'last_updated': firestore.SERVER_TIMESTAMP, 'emails': { session['uid']: session['user_email'] }}, merge=True)
        
        # Threaded Email
        seller_doc = db.collection('users').document(data['seller_uid']).get()
        if seller_doc.exists:
            seller_email = seller_doc.to_dict().get('email')
            msg = Message('New Order Request!', sender='orders@unitrade.com', recipients=[seller_email])
            msg.body = f"Good news! Someone wants to buy your {data['item_name']}."
            Thread(target=send_async_email, args=(app, msg)).start()

        return jsonify({'success': True, 'message': 'Request sent to seller!'})
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/handle_order', methods=['POST'])
@login_required
def api_handle_order():
    data = request.get_json()
    try:
        order_ref = db.collection('transactions').document(data['order_id'])
        order = order_ref.get()
        if not order.exists or order.to_dict()['seller_uid'] != session['uid']: return jsonify({'success': False}), 403
        
        status = 'completed' if data['action'] == 'accept' else 'rejected'
        order_ref.update({'status': status})
        if status == 'completed': 
            db.collection('products').document(order.to_dict()['item_id']).update({'status': 'sold'})
            db.collection('users').document(session['uid']).update({'sold_count': firestore.Increment(1)})
        return jsonify({'success': True, 'message': 'Order ' + status})
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/report', methods=['POST'])
@login_required
def api_report():
    data = request.get_json()
    try:
        item_ref = db.collection('products' if data['item_type'] == 'product' else 'services').document(data['item_id'])
        item = item_ref.get()
        if not item.exists: return jsonify({'success': False, 'message': 'Not found'}), 404
        db.collection('reports').add({
            'reporter_uid': session['uid'], 'reporter_email': session['user_email'],
            'item_id': data['item_id'], 'item_type': data['item_type'],
            'item_name': item.to_dict().get('name') or item.to_dict().get('service_type'),
            'item_image': item.to_dict().get('image_url'), 'reason': data['reason'], 'status': 'pending', 'timestamp': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'success': True, 'message': 'Report submitted.'})
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admin_action', methods=['POST'])
@login_required
def api_admin_action():
    if session.get('user_email') not in ADMIN_EMAILS: return jsonify({'success': False}), 403
    data = request.get_json()
    action = data.get('action')
    try:
        if action in ['approve_seller', 'reject_seller']:
            app_id = data.get('report_id'); app_ref = db.collection('seller_applications').document(app_id); app_doc = app_ref.get().to_dict(); user_uid = app_doc['uid']
            status = 'approved' if action == 'approve_seller' else 'rejected'
            db.collection('users').document(user_uid).update({'seller_status': status})
            app_ref.update({'status': status})
            return jsonify({'success': True, 'message': 'Seller ' + status})
        report_ref = db.collection('reports').document(data['report_id'])
        report = report_ref.get().to_dict()
        if action == 'delete_item':
            col = 'products' if report['item_type'] == 'product' else 'services'
            db.collection(col).document(report['item_id']).delete()
            report_ref.update({'status': 'resolved_banned'})
        elif action == 'dismiss': report_ref.update({'status': 'dismissed'})
        return jsonify({'success': True, 'message': 'Action taken.'})
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/delete_product', methods=['POST'])
def api_delete_product():
    data = request.get_json()
    try:
        prod_ref = db.collection('products').document(data['product_id'])
        prod = prod_ref.get()
        if prod.exists and prod.to_dict().get('seller_uid') == session['uid']:
            prod_ref.delete(); return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Error'}), 400
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/update_profile', methods=['POST'])
def api_update_profile():
    data = request.get_json()
    try:
        db.collection('users').document(session['uid']).update({
            'full_name': data['full_name'], 'phone_number': data['phone_number'], 'faculty': data['faculty']
        })
        return jsonify({'success': True, 'message': 'Updated.'})
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/add_review', methods=['POST'])
@login_required
def api_add_review():
    data = request.get_json()
    try:
        db.collection('users').document(data['target_uid']).collection('reviews').add({
            'reviewer_email': session['user_email'], 'rating': int(data['rating']), 'comment': data['comment'], 'timestamp': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'success': True, 'message': 'Review submitted!'})
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/submit_verification', methods=['POST'])
@login_required
def api_submit_verification():
    data = request.get_json(); uid = session['uid']
    try:
        db.collection('seller_applications').add({'uid': uid, 'email': session['user_email'], 'real_name': data['real_name'], 'nric': data['nric'], 'matric': data['matric'], 'id_card_url': data['id_card_url'], 'status': 'pending', 'timestamp': firestore.SERVER_TIMESTAMP})
        db.collection('users').document(uid).update({'seller_status': 'pending'})
        return jsonify({'success': True, 'message': 'Application submitted.'})
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

# AI DESCRIPTION GENERATOR
@app.route('/api/generate_desc', methods=['POST'])
@login_required
def generate_desc():
    data = request.get_json()
    item_name = data.get('name')
    category = data.get('category')
    condition = data.get('condition')

    if not item_name:
        return jsonify({'success': False, 'message': 'Please enter an item name first.'})

    try:
        # Create a prompt for the AI
        prompt = f"""
        Write a short, catchy, and professional sales description for a student marketplace listing.
        Item: {item_name}
        Category: {category}
        Condition: {condition}
        Target Audience: University Students.
        Keep it under 50 words. Do not use hashtags.
        """
        
        response = model.generate_content(prompt)
        description = response.text.strip()
        
        return jsonify({'success': True, 'description': description})
        
    except Exception as e:
        print(f"AI Error: {e}")
        return jsonify({'success': False, 'message': 'AI is busy. Please write manually.'})

# --- AI SCAM DETECTOR (Silent Flagging Version) ---
def check_is_scam(text):
    print(f"DEBUG: Checking message for scam: {text}")

    try:
        prompt = f"""
        You are a security AI for a student marketplace in Malaysia. Analyze this message.
        
        CONTEXT RULES:
        - Students use "Manglish", "Bahasa Rojak", and Malay shortforms (e.g., "x nak", "yg", "blh", "cod"). THIS IS NORMAL.
        - Do NOT flag a message as a scam just because of shortforms or informal grammar.
        - ONLY flag if the intent is malicious (phishing, courier scams, bots).

        SCAM INDICATORS (Return "SCAM"):
        1. Sharing contact info (WhatsApp/Telegram) as the VERY FIRST message.
        2. Mentions "Lalamove", "GrabExpress", or "Runner" picking up item without viewing.
        3. Very formal English + High Urgency ("Kindly pay now", "Dear Sir").
        4. Sending a suspicious link immediately.
        5. Asking for money upfront without negotiation.

        SAFE INDICATORS (Return "SAFE"):
        1. Discussing price, condition, or location.
        2. Sharing phone number to meet up (e.g., "watsap me 012...").
        3. Casual student language / Malay Shortform (e.g., "bro can nego?", "meet at library?", "barang ada lagi?").

        Message: "{text}"
        
        Reply ONLY with "SCAM" or "SAFE".
        """
        
        safety_settings = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        ]

        response = model.generate_content(prompt, safety_settings=safety_settings)

        if not response.parts: return False

        ai_reply = response.text.strip().upper()
        
        #If AI said "SAFE", return False and "if "SCAM", return True
        if "SCAM" in ai_reply or "WARNING" in ai_reply:
            return True
        
        return False

    except Exception as e:
        print(f"CRITICAL AI ERROR: {e}") 
        return False

# --- API ROUTE (Silent Flagging Implementation) ---
@app.route('/api/send_message', methods=['POST'])
@login_required
def api_send_message():
    try:
        # --- DEBUG LOGGING ---
        print("DEBUG: Entering send_message route")
        data = request.get_json()
        text = data.get('text')
        room_id = data.get('room_id')
        user_uid = session.get('uid') 

        print(f"DEBUG: Text: {text}, Room ID: {room_id}, User: {user_uid}")

        if not room_id:
            print("ERROR: Room ID is missing!")
            return jsonify({'success': False, 'message': 'Room ID missing'}), 400
        
        # 1. Run the AI Check
        is_suspicious = check_is_scam(text)
        
        # CHANGE: We NO LONGER block the message here.
        if is_suspicious:
            print("DEBUG: Message flagged as suspicious (Silent Flagging)")
        
        print("DEBUG: Preparing to save to DB...")

        message_data = {
            'text': text,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'sender_uid': user_uid,
            'is_suspicious': is_suspicious  # <--- SAVE THE FLAG TO DB
        }
        
        # 2. Save to Firestore (using .document)
        db.collection('chats').document(room_id).collection('messages').add(message_data)
        print("DEBUG: Message added to subcollection")

        # 3. Update Parent Doc
        db.collection('chats').document(room_id).set({
            'last_message': text,
            'last_updated': firestore.SERVER_TIMESTAMP
        }, merge=True)
        print("DEBUG: Parent doc updated")
        
        # 4. ALWAYS return success to the sender (so scammers don't know they are caught)
        return jsonify({'success': True})

    except Exception as e:
        print(f"CRITICAL SERVER ERROR: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Server Error'}), 500

if __name__ == '__main__':
    app.run(debug=True)