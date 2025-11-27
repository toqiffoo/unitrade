import os
import json 
import random  # <--- Added
import string  # <--- Added
import firebase_admin
from firebase_admin import credentials, auth, firestore, storage
from flask import Flask, render_template, request, redirect, url_for, session, make_response, jsonify
from flask_mail import Mail, Message # <--- Added
import google.auth.transport.requests

# --- CONFIGURATION & DATABASE CONNECTION ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'YOUR_VERY_STRONG_SECRET_KEY_FOR_SESSIONS' 

# Looking to send emails in production? Check out our Email API/SMTP product!
app.config['MAIL_SERVER']='sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = 'cad59bfc8c172b'
app.config['MAIL_PASSWORD'] = '5856f8bc0a3f03'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

# --- CRITICAL FIX: INITIALIZE MAIL ---
mail = Mail(app) 

KEY_FILE_NAME = 'key.json' 
STORAGE_BUCKET = "unitrade-839f0.firebasestorage.app" 

# --- ADMIN CONFIGURATION ---
ADMIN_EMAILS = ["test@unitrade.com"]

# Initialize variables
db = None
bucket = None
cred = None

# 1. Check for Local Key File (Your Computer)
if os.path.exists(KEY_FILE_NAME):
    cred = credentials.Certificate(KEY_FILE_NAME)

# 2. Check for Environment Variable (Render Cloud)
elif os.environ.get('FIREBASE_CREDENTIALS'):
    creds_json = json.loads(os.environ.get('FIREBASE_CREDENTIALS'))
    cred = credentials.Certificate(creds_json)

# 3. Connect to Firebase
if cred:
    if not firebase_admin._apps:
        firebase_admin.initialize_app(cred, {'storageBucket': STORAGE_BUCKET})
    
    db = firestore.client()
    bucket = storage.bucket()
else:
    print("WARNING: No credentials found. Database will not work.")

# --- HELPER FUNCTIONS ---
def login_required(f):
    def wrap(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

def get_chat_room_id(uid1, uid2):
    return '_'.join(sorted([uid1, uid2]))

# --- FLASK ROUTES ---

@app.route('/')
def index():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')

@app.route('/register', methods=['GET'])
def register():
    return render_template('signup.html')

@app.route('/dashboard')
@login_required 
def dashboard():
    global db
    user_email = session.get('user_email', 'User')
    
    # 1. Check if the current user is an Admin
    is_admin = user_email in ADMIN_EMAILS 

    search_query = request.args.get('q', '').lower()
    products = []
    services = []

    try:
        # Fetch Products
        products_ref = db.collection('products').order_by('created_at', direction=firestore.Query.DESCENDING).stream()
        for doc in products_ref:
            p = doc.to_dict()
            p['id'] = doc.id
            if search_query:
                if search_query in p.get('name', '').lower() or search_query in p.get('description', '').lower():
                    products.append(p)
            else:
                products.append(p)

        # Fetch Services
        services_ref = db.collection('services').order_by('created_at', direction=firestore.Query.DESCENDING).stream()
        for doc in services_ref:
            s = doc.to_dict()
            s['id'] = doc.id
            if search_query:
                if search_query in s.get('service_type', '').lower() or search_query in s.get('description', '').lower():
                    services.append(s)
            else:
                services.append(s)
            
    except Exception as e:
        print(f"Error fetching data: {e}")

    return render_template('dashboard.html', user_email=user_email, products=products, services=services, is_admin=is_admin)

@app.route('/inbox')
@login_required
def inbox():
    global db
    current_uid = session.get('uid')
    chat_list = []
    try:
        chats_ref = db.collection('chats').where('participants', 'array_contains', current_uid).stream()
        for doc in chats_ref:
            data = doc.to_dict()
            participants = data.get('participants', [])
            emails = data.get('emails', {})
            other_uid = next((uid for uid in participants if uid != current_uid), None)
            
            if other_uid:
                chat_list.append({
                    'other_uid': other_uid,
                    'other_email': emails.get(other_uid, 'Unknown User'),
                    'last_message': data.get('last_message', 'No messages yet')
                })
    except Exception as e:
        print(f"Error loading inbox: {e}")
    return render_template('inbox.html', chats=chat_list)

@app.route('/sell', methods=['GET'])
@login_required 
def sell():
    return render_template('sell.html')

@app.route('/offer_service', methods=['GET'])
@login_required 
def offer_service():
    return render_template('services.html')

@app.route('/profile')
@login_required 
def profile():
    global db
    current_uid = session.get('uid')
    user_products = []
    user_services = []
    user_info = {}

    try:
        user_doc = db.collection('users').document(current_uid).get()
        if user_doc.exists:
            user_info = user_doc.to_dict()

        products_ref = db.collection('products').where('seller_uid', '==', current_uid).stream()
        for doc in products_ref:
            p = doc.to_dict()
            p['id'] = doc.id
            user_products.append(p)

        services_ref = db.collection('services').where('provider_uid', '==', current_uid).stream()
        for doc in services_ref:
            s = doc.to_dict()
            s['id'] = doc.id
            user_services.append(s)

    except Exception as e:
        print(f"Error loading profile: {e}")

    return render_template('profile.html', products=user_products, services=user_services, user=user_info)

@app.route('/settings')
@login_required 
def settings():
    current_uid = session.get('uid')
    user_info = {}
    try:
        user_doc = db.collection('users').document(current_uid).get()
        if user_doc.exists:
            user_info = user_doc.to_dict()
    except Exception:
        pass
    return render_template('settings.html', user=user_info)

@app.route('/chat/<seller_uid>', methods=['GET'])
@login_required
def chat(seller_uid):
    current_uid = session.get('uid')
    current_email = session.get('user_email')
    room_id = get_chat_room_id(current_uid, seller_uid)
    try:
        opponent_doc = db.collection('users').document(seller_uid).get()
        opponent_email = opponent_doc.to_dict().get('email', 'Seller')
    except Exception:
        opponent_email = 'Unknown Seller'
    return render_template('chat.html', room_id=room_id, opponent_email=opponent_email, seller_uid=seller_uid, current_uid=current_uid, current_email=current_email)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login')) 

# --- API ROUTES ---

@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.get_json()
    email = data.get('email')
    phone_number = data.get('phoneNumber') 
    full_name = data.get('fullName', 'Student')
    password = data.get('password')
    try:
        try:
            user = auth.create_user(email=email, password=password)
            uid = user.uid
        except firebase_admin.exceptions.FirebaseError:
            user = auth.get_user_by_email(email)
            uid = user.uid
        db.collection('users').document(uid).set({
            'email': email,
            'full_name': full_name,
            'phone_number': phone_number, 
            'created_at': firestore.SERVER_TIMESTAMP
        }, merge=True)
        return jsonify({'success': True, 'message': 'Account created.'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# 1. MODIFIED LOGIN: Generate OTP
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    try:
        # Verify Token (Clock skew fix included)
        decoded_token = auth.verify_id_token(data['idToken'], clock_skew_seconds=60)
        uid = decoded_token['uid']
        email = data['email']

        # Generate OTP
        otp = ''.join(random.choices(string.digits, k=6))
        
        # Store in Session
        session['temp_uid'] = uid
        session['temp_email'] = email
        session['mfa_otp'] = otp
        
        # Send Email via Mailtrap
        msg = Message('Your UniTrade Login Code', sender='security@unitrade.com', recipients=[email])
        msg.body = f"Your verification code is: {otp}"
        mail.send(msg)
        
        print(f"DEBUG: Sent OTP {otp} to {email}")

        return jsonify({'success': True, 'mfa_required': True, 'message': 'OTP sent! Check your email.'})

    except Exception as e:
        print(f"Login Error: {e}")
        return jsonify({'success': False, 'message': 'Login failed.'}), 401

# 2. NEW ROUTE: Verify OTP
@app.route('/api/verify_mfa', methods=['POST'])
def api_verify_mfa():
    data = request.get_json()
    user_otp = data.get('otp')
    
    if 'mfa_otp' in session and session['mfa_otp'] == user_otp:
        # Success! Log them in fully.
        session['logged_in'] = True
        session['uid'] = session['temp_uid']
        session['user_email'] = session['temp_email']
        
        # Clean up temp session
        session.pop('temp_uid', None)
        session.pop('temp_email', None)
        session.pop('mfa_otp', None)
        
        return jsonify({'success': True, 'redirect_url': url_for('dashboard')})
    else:
        return jsonify({'success': False, 'message': 'Invalid Code'}), 400

@app.route('/api/sell', methods=['POST'])
def api_sell():
    data = request.get_json()
    id_token = data.get('idToken') 
    try:
        decoded_token = auth.verify_id_token(id_token)
        user_uid = decoded_token['uid']
        user_name = "Student Seller"
        user_doc = db.collection('users').document(user_uid).get()
        if user_doc.exists:
            user_name = user_doc.to_dict().get('full_name', 'Student Seller')

        db.collection('products').add({
            'seller_uid': user_uid,
            'seller_email': decoded_token.get('email'),
            'seller_name': user_name,
            'name': data.get('name'),
            'description': data.get('description'),
            'price': float(data.get('price')),
            'image_url': data.get('image_url'), 
            'created_at': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'success': True, 'redirect_url': url_for('dashboard')})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/offer_service', methods=['POST'])
def api_offer_service():
    data = request.get_json()
    id_token = data.get('idToken') 
    try:
        decoded_token = auth.verify_id_token(id_token)
        user_uid = decoded_token['uid']
        user_name = "Student Provider"
        user_doc = db.collection('users').document(user_uid).get()
        if user_doc.exists:
            user_name = user_doc.to_dict().get('full_name', 'Student Provider')

        db.collection('services').add({
            'provider_uid': user_uid,
            'provider_email': decoded_token.get('email'),
            'provider_name': user_name,
            'service_type': data.get('service_type'), 
            'description': data.get('description'),
            'price': float(data.get('price')),
            'image_url': data.get('image_url'), 
            'is_available': True,
            'created_at': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'success': True, 'redirect_url': url_for('dashboard')})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/toggle_service', methods=['POST'])
def api_toggle_service():
    data = request.get_json()
    service_id = data.get('service_id')
    new_status = data.get('status')
    
    try:
        service_ref = db.collection('services').document(service_id)
        service = service_ref.get()
        if service.exists and service.to_dict().get('provider_uid') == session['uid']:
            service_ref.update({'is_available': new_status})
            return jsonify({'success': True, 'message': 'Status updated.'})
        return jsonify({'success': False, 'message': 'Unauthorized.'}), 403
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/delete_product', methods=['POST'])
def api_delete_product():
    data = request.get_json()
    product_id = data.get('product_id')
    try:
        prod_ref = db.collection('products').document(product_id)
        prod = prod_ref.get()
        if prod.exists:
            prod_data = prod.to_dict()
            if prod_data.get('seller_uid') == session['uid']:
                image_url = prod_data.get('image_url', '')
                if image_url:
                    try:
                        from urllib.parse import unquote
                        path_start = image_url.find('/o/') + 3
                        path_end = image_url.find('?')
                        file_path = unquote(image_url[path_start:path_end])
                        blob = bucket.blob(file_path)
                        blob.delete()
                    except Exception as img_err:
                        print(f"Image delete warning: {img_err}")
                prod_ref.delete()
                return jsonify({'success': True, 'message': 'Item deleted.'})
            else:
                return jsonify({'success': False, 'message': 'Unauthorized.'}), 403
        return jsonify({'success': False, 'message': 'Product not found.'}), 404
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/update_profile', methods=['POST'])
def api_update_profile():
    data = request.get_json()
    uid = session.get('uid')
    try:
        db.collection('users').document(uid).update({
            'full_name': data.get('full_name'),
            'phone_number': data.get('phone_number')
        })
        return jsonify({'success': True, 'message': 'Profile updated.'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# --- ADMIN & REPORTING ROUTES ---

@app.route('/admin')
@login_required
def admin_dashboard():
    user_email = session.get('user_email')
    if user_email not in ADMIN_EMAILS:
        return "Access Denied: You are not an administrator.", 403

    reports = []
    try:
        reports_ref = db.collection('reports').order_by('timestamp', direction=firestore.Query.DESCENDING).stream()
        for doc in reports_ref:
            r = doc.to_dict()
            r['id'] = doc.id
            reports.append(r)
    except Exception as e:
        print(f"Admin Error: {e}")

    return render_template('admin.html', reports=reports)

@app.route('/api/report', methods=['POST'])
@login_required
def api_report():
    data = request.get_json()
    item_id = data.get('item_id')
    item_type = data.get('item_type')
    reason = data.get('reason')
    
    try:
        item_ref = db.collection('products' if item_type == 'product' else 'services').document(item_id)
        item = item_ref.get()
        if not item.exists: return jsonify({'success': False, 'message': 'Item not found.'}), 404
        item_data = item.to_dict()
        
        db.collection('reports').add({
            'reporter_uid': session['uid'],
            'reporter_email': session['user_email'],
            'item_id': item_id,
            'item_type': item_type,
            'item_name': item_data.get('name') if item_type == 'product' else item_data.get('service_type'),
            'item_image': item_data.get('image_url'),
            'reason': reason,
            'status': 'pending',
            'timestamp': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'success': True, 'message': 'Report submitted to Admin.'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admin_action', methods=['POST'])
@login_required
def api_admin_action():
    if session.get('user_email') not in ADMIN_EMAILS:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.get_json()
    try:
        report_ref = db.collection('reports').document(data['report_id'])
        report = report_ref.get().to_dict()
        
        if data['action'] == 'delete_item':
            col = 'products' if report['item_type'] == 'product' else 'services'
            db.collection(col).document(report['item_id']).delete()
            report_ref.update({'status': 'resolved_banned'})
            message = "Item deleted and user flagged."
        elif data['action'] == 'dismiss':
            report_ref.update({'status': 'dismissed'})
            message = "Report dismissed."
        return jsonify({'success': True, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# --- MAIN EXECUTION ---
if __name__ == '__main__':
    app.run(debug=True)