import os
import json 
import random
import string
import datetime # <--- Added for timestamps
import firebase_admin
from firebase_admin import credentials, auth, firestore, storage
from flask import Flask, render_template, request, redirect, url_for, session, make_response, jsonify
from flask_mail import Mail, Message
import google.auth.transport.requests

# --- CONFIGURATION & DATABASE CONNECTION ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'YOUR_VERY_STRONG_SECRET_KEY_FOR_SESSIONS' 

# Looking to send emails in production? Check out our Email API/SMTP product!
app.config['MAIL_SERVER']='sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'cad59bfc8c172b'
app.config['MAIL_PASSWORD'] = '5856f8bc0a3f03'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app) 

KEY_FILE_NAME = 'key.json' 
STORAGE_BUCKET = "unitrade-839f0.firebasestorage.app" 

# --- ADMIN CONFIGURATION ---
ADMIN_EMAILS = ["test@unitrade.com"]

# Initialize variables
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
    current_uid = session.get('uid') # Needed for fetching orders
    is_admin = user_email in ADMIN_EMAILS 
    search_query = request.args.get('q', '').lower()
    
    products = []
    services = []
    orders = [] # NEW: List for incoming buy requests

    try:
        # 1. Fetch Products (Exclude sold ones)
        products_ref = db.collection('products').order_by('created_at', direction=firestore.Query.DESCENDING).stream()
        for doc in products_ref:
            p = doc.to_dict()
            p['id'] = doc.id
            if p.get('status') != 'sold': 
                if not search_query or (search_query in p.get('name', '').lower() or search_query in p.get('description', '').lower()):
                    products.append(p)

        # 2. Fetch Services
        services_ref = db.collection('services').order_by('created_at', direction=firestore.Query.DESCENDING).stream()
        for doc in services_ref:
            s = doc.to_dict()
            s['id'] = doc.id
            if not search_query or (search_query in s.get('service_type', '').lower() or search_query in s.get('description', '').lower()):
                services.append(s)

        # 3. NEW: Fetch Incoming Orders for this Seller
        orders_ref = db.collection('transactions').where('seller_uid', '==', current_uid).where('status', '==', 'pending_approval').stream()
        for doc in orders_ref:
            o = doc.to_dict()
            o['id'] = doc.id
            orders.append(o)
            
    except Exception as e:
        print(f"Error fetching data: {e}")

    return render_template('dashboard.html', 
                           user_email=user_email, 
                           products=products, 
                           services=services, 
                           orders=orders, # Pass orders to template
                           is_admin=is_admin)

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
        if user_doc.exists: user_info = user_doc.to_dict()
        
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
        if user_doc.exists: user_info = user_doc.to_dict()
    except Exception: pass
    return render_template('settings.html', user=user_info)

# UPDATED: Chat route now accepts item_id to show context
@app.route('/chat/<seller_uid>', methods=['GET'])
@login_required
def chat(seller_uid):
    current_uid = session.get('uid')
    current_email = session.get('user_email')
    room_id = get_chat_room_id(current_uid, seller_uid)
    
    # Get Item Context (if user clicked "Chat" from a specific item)
    item_id = request.args.get('item_id')
    item_context = None
    
    try:
        opponent_doc = db.collection('users').document(seller_uid).get()
        opponent_email = opponent_doc.to_dict().get('email', 'Seller')
        
        if item_id:
            # Try finding it in products first
            item_doc = db.collection('products').document(item_id).get()
            if not item_doc.exists:
                item_doc = db.collection('services').document(item_id).get()
            
            if item_doc.exists:
                item_context = item_doc.to_dict()
                item_context['id'] = item_id # Add ID for reference
                
    except Exception:
        opponent_email = 'Unknown Seller'

    return render_template('chat.html', 
                           room_id=room_id, 
                           opponent_email=opponent_email, 
                           seller_uid=seller_uid, 
                           current_uid=current_uid, 
                           current_email=current_email,
                           item_context=item_context)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login')) 

@app.route('/admin')
@login_required
def admin_dashboard():
    if session.get('user_email') not in ADMIN_EMAILS:
        return "Access Denied", 403
    reports = []
    try:
        reports_ref = db.collection('reports').order_by('timestamp', direction=firestore.Query.DESCENDING).stream()
        for doc in reports_ref:
            r = doc.to_dict()
            r['id'] = doc.id
            reports.append(r)
    except Exception: pass
    return render_template('admin.html', reports=reports)

# --- API ROUTES ---

@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.get_json()
    try:
        try:
            user = auth.create_user(email=data['email'], password=data['password'])
            uid = user.uid
        except:
            user = auth.get_user_by_email(data['email'])
            uid = user.uid
        
        db.collection('users').document(uid).set({
            'email': data['email'],
            'full_name': data.get('fullName'),
            'phone_number': data.get('phoneNumber'), 
            'created_at': firestore.SERVER_TIMESTAMP
        }, merge=True)
        return jsonify({'success': True, 'message': 'Account created.'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    try:
        decoded_token = auth.verify_id_token(data['idToken'], clock_skew_seconds=60)
        uid = decoded_token['uid']
        email = data['email']

        otp = ''.join(random.choices(string.digits, k=6))
        session['temp_uid'] = uid
        session['temp_email'] = email
        session['mfa_otp'] = otp
        
        msg = Message('Your UniTrade Login Code', sender='security@unitrade.com', recipients=[email])
        msg.body = f"Your verification code is: {otp}"
        mail.send(msg)
        print(f"DEBUG: Sent OTP {otp} to {email}")

        return jsonify({'success': True, 'mfa_required': True, 'message': 'OTP sent! Check your email.'})
    except Exception as e:
        print(f"Login Error: {e}")
        return jsonify({'success': False, 'message': 'Login failed.'}), 401

@app.route('/api/verify_mfa', methods=['POST'])
def api_verify_mfa():
    data = request.get_json()
    if 'mfa_otp' in session and session['mfa_otp'] == data.get('otp'):
        session['logged_in'] = True
        session['uid'] = session['temp_uid']
        session['user_email'] = session['temp_email']
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
            'seller_uid': user_uid,
            'seller_email': decoded_token.get('email'),
            'seller_name': user_name,
            'name': data.get('name'),
            'description': data.get('description'),
            'price': float(data.get('price')),
            'image_url': data.get('image_url'), 
            'status': 'available', # New field for Buy Logic
            'created_at': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'success': True, 'redirect_url': url_for('dashboard')})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/offer_service', methods=['POST'])
def api_offer_service():
    data = request.get_json()
    try:
        decoded_token = auth.verify_id_token(data['idToken'])
        user_uid = decoded_token['uid']
        user_doc = db.collection('users').document(user_uid).get()
        user_name = user_doc.to_dict().get('full_name', 'Provider') if user_doc.exists else 'Provider'

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

# NEW: API to Handle Buying Requests
@app.route('/api/buy_request', methods=['POST'])
@login_required
def api_buy_request():
    data = request.get_json()
    try:
        # Create Transaction Record
        db.collection('transactions').add({
            'buyer_uid': session['uid'],
            'buyer_email': session['user_email'],
            'seller_uid': data['seller_uid'],
            'item_id': data['item_id'],
            'item_name': data['item_name'],
            'payment_method': data['payment_method'], # 'COD' or 'Online'
            'proof_image': data.get('proof_image'),   # Optional for COD
            'status': 'pending_approval',
            'created_at': firestore.SERVER_TIMESTAMP
        })
        
        # Determine Chat Room ID
        room_id = get_chat_room_id(session['uid'], data['seller_uid'])
        
        # Auto-send a message to the seller so they see the request
        msg_text = f"📢 I have requested to buy '{data['item_name']}' via {data['payment_method']}."
        if data.get('proof_image'):
            msg_text += " (Payment Receipt Attached)"
            
        db.collection('chats').doc(room_id).collection('messages').add({
            'text': msg_text,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'sender_uid': session['uid']
        })
        
        # Ensure chat is visible in Inbox
        db.collection('chats').doc(room_id).set({
            'participants': [session['uid'], data['seller_uid']],
            'last_message': "New Buy Request",
            'last_updated': firestore.SERVER_TIMESTAMP,
            'emails': { session['uid']: session['user_email'] } # In a real app, fetch seller email too
        }, merge=True)

        return jsonify({'success': True, 'message': 'Request sent to seller!'})
    except Exception as e:
        print(f"Buy Error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/report', methods=['POST'])
@login_required
def api_report():
    data = request.get_json()
    try:
        item_ref = db.collection('products' if data['item_type'] == 'product' else 'services').document(data['item_id'])
        item = item_ref.get()
        if not item.exists: return jsonify({'success': False, 'message': 'Not found'}), 404
        
        db.collection('reports').add({
            'reporter_uid': session['uid'],
            'reporter_email': session['user_email'],
            'item_id': data['item_id'],
            'item_type': data['item_type'],
            'item_name': item.to_dict().get('name') or item.to_dict().get('service_type'),
            'item_image': item.to_dict().get('image_url'),
            'reason': data['reason'],
            'status': 'pending',
            'timestamp': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'success': True, 'message': 'Report submitted.'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admin_action', methods=['POST'])
@login_required
def api_admin_action():
    if session.get('user_email') not in ADMIN_EMAILS: return jsonify({'success': False}), 403
    data = request.get_json()
    try:
        report_ref = db.collection('reports').document(data['report_id'])
        report = report_ref.get().to_dict()
        if data['action'] == 'delete_item':
            col = 'products' if report['item_type'] == 'product' else 'services'
            db.collection(col).document(report['item_id']).delete()
            report_ref.update({'status': 'resolved_banned'})
        elif data['action'] == 'dismiss':
            report_ref.update({'status': 'dismissed'})
        return jsonify({'success': True, 'message': 'Action taken.'})
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/delete_product', methods=['POST'])
def api_delete_product():
    data = request.get_json()
    try:
        prod_ref = db.collection('products').document(data['product_id'])
        prod = prod_ref.get()
        if prod.exists and prod.to_dict().get('seller_uid') == session['uid']:
            prod_ref.delete()
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Error'}), 400
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/update_profile', methods=['POST'])
def api_update_profile():
    data = request.get_json()
    try:
        db.collection('users').document(session['uid']).update({
            'full_name': data['full_name'], 'phone_number': data['phone_number']
        })
        return jsonify({'success': True, 'message': 'Updated.'})
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500

    # NEW: Handle Accept/Reject Order
@app.route('/api/handle_order', methods=['POST'])
@login_required
def api_handle_order():
    data = request.get_json()
    order_id = data.get('order_id')
    action = data.get('action') # 'accept' or 'reject'
    
    try:
        order_ref = db.collection('transactions').document(order_id)
        order = order_ref.get()
        
        if not order.exists: return jsonify({'success': False, 'message': 'Order not found'}), 404
        
        order_data = order.to_dict()
        
        # Verify this user is the actual seller
        if order_data['seller_uid'] != session['uid']:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403

        if action == 'accept':
            # 1. Update Order Status
            order_ref.update({'status': 'completed'})
            
            # 2. Mark Product as SOLD
            db.collection('products').document(order_data['item_id']).update({'status': 'sold'})
            
            # 3. Notify Buyer (Optional: You could add a chat message here)
            message = "Order Accepted! Item marked as Sold."
            
        elif action == 'reject':
            order_ref.update({'status': 'rejected'})
            message = "Order Rejected."

        return jsonify({'success': True, 'message': message})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)