import os
import secrets
import string
from datetime import datetime, timedelta
import sqlite3
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
import pandas as pd
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hfXFDFdfdfdf5dg52fgfgfdkVCGFgkdf5'
CORS(app)  # Enable CORS for all routes
DATABASE = 'activation_keys.db'

# Database initialization
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Create tables if they don't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS activation_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_value TEXT UNIQUE NOT NULL,
        key_type TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT 1,
        is_banned BOOLEAN DEFAULT 0,
        activation_date TIMESTAMP NULL,
        hwid TEXT NULL,
        machine_id TEXT NULL,
        expiry_date TIMESTAMP NULL,
        email TEXT NULL,
        notes TEXT NULL,
        customer_name TEXT NULL,
        product_name TEXT NULL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        api_key TEXT UNIQUE NULL,
        is_superadmin BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP NULL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS key_types (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        duration_days INTEGER NOT NULL,
        description TEXT NULL,
        price REAL NULL,
        is_available BOOLEAN DEFAULT 1
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        description TEXT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT 1
    )
    ''')

    # Insert default key types if they don't exist
    default_key_types = [
        ('7day', 7, '7 Day License', 9.99),
        ('month', 30, '1 Month License', 29.99),
        ('6month', 180, '6 Month License', 149.99),
        ('1year', 365, '1 Year License', 249.99),
        ('lifetime', 36500, 'Lifetime License', 499.99)
    ]

    for key_type in default_key_types:
        cursor.execute('''
        INSERT OR IGNORE INTO key_types (name, duration_days, description, price)
        VALUES (?, ?, ?, ?)
        ''', key_type)

    # Create default admin if none exists
    cursor.execute('SELECT COUNT(*) FROM admin_users')
    if cursor.fetchone()[0] == 0:
        password_hash = generate_password_hash('admin')
        api_key = 'bc3eabae-7ee2-40fa-b19b-53f1bfd3c8ad'  # Fixed API key for demo
        cursor.execute('''
        INSERT INTO admin_users (username, password_hash, api_key, is_superadmin) 
        VALUES (?, ?, ?, ?)
        ''', ('admin', password_hash, api_key, 1))

    conn.commit()
    conn.close()

# Generate a secure API key
def generate_api_key():
    return str(uuid.uuid4())

# Admin user management
def create_admin(username, password, is_superadmin=False):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    password_hash = generate_password_hash(password)
    api_key = generate_api_key()
    try:
        cursor.execute('''
        INSERT INTO admin_users (username, password_hash, api_key, is_superadmin) 
        VALUES (?, ?, ?, ?)
        ''', (username, password_hash, api_key, is_superadmin))
        conn.commit()
        return api_key
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def verify_admin(username, password):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
    SELECT password_hash, api_key FROM admin_users 
    WHERE username = ?
    ''', (username,))
    result = cursor.fetchone()
    conn.close()

    if result and check_password_hash(result[0], password):
        # Update last login time
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''
        UPDATE admin_users 
        SET last_login = CURRENT_TIMESTAMP 
        WHERE username = ?
        ''', (username,))
        conn.commit()
        conn.close()
        return result[1]  # Return API key
    return None

def get_admin_by_api_key(api_key):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
    SELECT username, is_superadmin 
    FROM admin_users 
    WHERE api_key = ?
    ''', (api_key,))
    result = cursor.fetchone()
    conn.close()
    return result if result else None

# Authentication decorators
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        api_key = request.headers.get('X-API-KEY')
        if not api_key or not get_admin_by_api_key(api_key):
            return jsonify({'success': False, 'message': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return wrapper

def superadmin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        api_key = request.headers.get('X-API-KEY')
        admin_info = get_admin_by_api_key(api_key) if api_key else None
        if not admin_info or not admin_info[1]:  # Check is_superadmin flag
            return jsonify({'success': False, 'message': 'Superadmin privileges required'}), 403
        return f(*args, **kwargs)
    return wrapper

# Key generation
def generate_key(prefix="ECP"):
    """Generate a random activation key with given prefix"""
    alphabet = string.ascii_uppercase + string.digits
    key_part = ''.join(secrets.choice(alphabet) for _ in range(12))
    return f"{prefix}-{key_part[:4]}-{key_part[4:8]}-{key_part[8:12]}"

def calculate_expiry_date(key_type):
    """Calculate expiry date based on key type"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
    SELECT duration_days FROM key_types WHERE name = ?
    ''', (key_type,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return datetime.now() + timedelta(days=result[0])
    return None

# Database operations
def add_keys_to_db(keys, key_type, customer_name=None, product_name=None, notes=None):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    expiry_date = calculate_expiry_date(key_type)

    for key in keys:
        try:
            cursor.execute('''
            INSERT INTO activation_keys (
                key_value, key_type, expiry_date, 
                customer_name, product_name, notes
            ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (key, key_type, expiry_date, customer_name, product_name, notes))
        except sqlite3.IntegrityError:
            continue  # Skip duplicate keys

    conn.commit()
    conn.close()

def ban_key(key_value):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
    UPDATE activation_keys 
    SET is_banned = 1, is_active = 0 
    WHERE key_value = ?
    ''', (key_value,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0

def unban_key(key_value):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
    UPDATE activation_keys 
    SET is_banned = 0, is_active = 1 
    WHERE key_value = ?
    ''', (key_value,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0

def activate_key(key_value, hwid=None, machine_id=None, email=None):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Check if key exists and is not banned
    cursor.execute('''
    SELECT is_banned, is_active, activation_date, key_type 
    FROM activation_keys 
    WHERE key_value = ?
    ''', (key_value,))
    result = cursor.fetchone()

    if not result:
        conn.close()
        return {'status': 'error', 'message': 'Key not found'}

    is_banned, is_active, activation_date, key_type = result

    if is_banned:
        conn.close()
        return {'status': 'error', 'message': 'Key is banned'}

    if activation_date:
        conn.close()
        return {'status': 'error', 'message': 'Key already activated'}

    # Activate the key
    expiry_date = calculate_expiry_date(key_type)
    cursor.execute('''
    UPDATE activation_keys 
    SET is_active = 1, 
        activation_date = CURRENT_TIMESTAMP,
        hwid = ?,
        machine_id = ?,
        email = ?,
        expiry_date = ?
    WHERE key_value = ?
    ''', (hwid, machine_id, email, expiry_date, key_value))

    conn.commit()
    conn.close()
    return {'status': 'success', 'message': 'Key activated successfully'}

def parse_datetime(dt_str):
    """Parse datetime string, handling microseconds if present"""
    if not dt_str:
        return None
    try:
        # Try parsing with microseconds
        return datetime.strptime(dt_str, '%Y-%m-%d %H:%M:%S.%f')
    except ValueError:
        try:
            # Try parsing without microseconds
            return datetime.strptime(dt_str, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return None

def check_key_status(key_value):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute('''
    SELECT 
        key_value, 
        key_type, 
        is_active, 
        is_banned, 
        activation_date, 
        expiry_date,
        hwid,
        machine_id,
        email,
        customer_name,
        product_name,
        notes,
        created_at
    FROM activation_keys 
    WHERE key_value = ?
    ''', (key_value,))

    result = cursor.fetchone()
    conn.close()

    if not result:
        return {'status': 'error', 'message': 'Key not found'}

    # Parse datetime fields
    activation_date = parse_datetime(result[4])
    expiry_date = parse_datetime(result[5])
    created_at = parse_datetime(result[12])

    # Check if key is valid
    is_valid = (
        not bool(result[3]) and  # not banned
        bool(result[2]) and      # is active
        (not expiry_date or expiry_date > datetime.now())  # not expired
    )

    key_data = {
        'key': result[0],
        'type': result[1],
        'is_active': bool(result[2]),
        'is_banned': bool(result[3]),
        'activation_date': activation_date.isoformat() if activation_date else None,
        'expiry_date': expiry_date.isoformat() if expiry_date else None,
        'hwid': result[6],
        'machine_id': result[7],
        'email': result[8],
        'customer_name': result[9],
        'product_name': result[10],
        'notes': result[11],
        'created_at': created_at.isoformat() if created_at else None,
        'is_valid': is_valid
    }

    return {'status': 'success', 'data': key_data}

def get_all_keys(page=1, per_page=100, filters=None):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Base query
    query = '''
    SELECT 
        key_value,
        key_type,
        is_active,
        is_banned,
        activation_date,
        expiry_date,
        hwid,
        machine_id,
        email,
        customer_name,
        product_name,
        notes,
        created_at
    FROM activation_keys
    '''

    # Add filters if provided
    params = []
    where_clauses = []

    if filters:
        if 'key_type' in filters:
            where_clauses.append('key_type = ?')
            params.append(filters['key_type'])
        if 'is_active' in filters:
            where_clauses.append('is_active = ?')
            params.append(int(filters['is_active']))
        if 'is_banned' in filters:
            where_clauses.append('is_banned = ?')
            params.append(int(filters['is_banned']))
        if 'customer_name' in filters:
            where_clauses.append('customer_name LIKE ?')
            params.append(f'%{filters["customer_name"]}%')
        if 'product_name' in filters:
            where_clauses.append('product_name LIKE ?')
            params.append(f'%{filters["product_name"]}%')
        if 'email' in filters:
            where_clauses.append('email LIKE ?')
            params.append(f'%{filters["email"]}%')

    if where_clauses:
        query += ' WHERE ' + ' AND '.join(where_clauses)

    # Add pagination
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'
    params.extend([per_page, (page - 1) * per_page])

    cursor.execute(query, params)
    results = cursor.fetchall()

    # Get total count for pagination
    count_query = 'SELECT COUNT(*) FROM activation_keys'
    if where_clauses:
        count_query += ' WHERE ' + ' AND '.join(where_clauses)

    cursor.execute(count_query, params[:-2])  # Exclude LIMIT and OFFSET params
    total = cursor.fetchone()[0]

    conn.close()

    # Format results
    keys = []
    for result in results:
        keys.append({
            'key_value': result[0],
            'key_type': result[1],
            'is_active': bool(result[2]),
            'is_banned': bool(result[3]),
            'activation_date': result[4],
            'expiry_date': result[5],
            'hwid': result[6],
            'machine_id': result[7],
            'email': result[8],
            'customer_name': result[9],
            'product_name': result[10],
            'notes': result[11],
            'created_at': result[12]
        })

    return {
        'keys': keys,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page
    }

def get_key_types():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
    SELECT name, duration_days, description, price, is_available 
    FROM key_types
    ORDER BY duration_days
    ''')
    results = cursor.fetchall()
    conn.close()

    key_types = []
    for result in results:
        key_types.append({
            'name': result[0],
            'duration_days': result[1],
            'description': result[2],
            'price': result[3],
            'is_available': bool(result[4])
        })

    return key_types

def get_customers():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
    SELECT 
        COALESCE(customer_name, 'Unknown') as name,
        '' as email,
        COUNT(*) as total_keys,
        SUM(CASE WHEN is_active = 1 AND is_banned = 0 THEN 1 ELSE 0 END) as active_keys,
        SUM(CASE WHEN activation_date IS NOT NULL THEN 1 ELSE 0 END) as activated_keys
    FROM activation_keys
    GROUP BY COALESCE(customer_name, 'Unknown')
    ORDER BY name
    ''')
    results = cursor.fetchall()
    conn.close()

    customers = []
    for result in results:
        customers.append({
            'name': result[0],
            'email': result[1],
            'total_keys': result[2],
            'active_keys': result[3],
            'activated_keys': result[4]
        })

    return customers

def get_products():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
    SELECT 
        COALESCE(product_name, 'Unknown') as name,
        COUNT(*) as total_keys,
        SUM(CASE WHEN is_active = 1 AND is_banned = 0 THEN 1 ELSE 0 END) as active_keys,
        SUM(CASE WHEN activation_date IS NOT NULL THEN 1 ELSE 0 END) as activated_keys,
        GROUP_CONCAT(DISTINCT key_type) as key_types
    FROM activation_keys
    GROUP BY COALESCE(product_name, 'Unknown')
    ORDER BY name
    ''')
    results = cursor.fetchall()
    conn.close()

    products = []
    for result in results:
        key_types = result[4].split(',') if result[4] else []
        products.append({
            'name': result[0],
            'total_keys': result[1],
            'active_keys': result[2],
            'activated_keys': result[3],
            'key_types': key_types
        })

    return products

def get_stats():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Total keys
    cursor.execute('SELECT COUNT(*) FROM activation_keys')
    total_keys = cursor.fetchone()[0]

    # Active keys
    cursor.execute('''
    SELECT COUNT(*) FROM activation_keys 
    WHERE is_active = 1 AND is_banned = 0
    ''')
    active_keys = cursor.fetchone()[0]

    # Banned keys
    cursor.execute('SELECT COUNT(*) FROM activation_keys WHERE is_banned = 1')
    banned_keys = cursor.fetchone()[0]

    # Activated keys
    cursor.execute('SELECT COUNT(*) FROM activation_keys WHERE activation_date IS NOT NULL')
    activated_keys = cursor.fetchone()[0]

    # Expired keys
    cursor.execute('''
    SELECT COUNT(*) FROM activation_keys 
    WHERE expiry_date < CURRENT_TIMESTAMP AND is_banned = 0
    ''')
    expired_keys = cursor.fetchone()[0]

    # Key types distribution
    cursor.execute('''
    SELECT key_type, COUNT(*) 
    FROM activation_keys 
    GROUP BY key_type
    ''')
    key_types_dist = {row[0]: row[1] for row in cursor.fetchall()}

    conn.close()

    return {
        'total_keys': total_keys,
        'active_keys': active_keys,
        'banned_keys': banned_keys,
        'activated_keys': activated_keys,
        'expired_keys': expired_keys,
        'key_types': key_types_dist
    }

# API Endpoints

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'success': True,
        'message': 'ECertifPro API is running',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/key-types')
def get_key_types_endpoint():
    """Get available key types"""
    key_types = get_key_types()
    return jsonify({
        'success': True,
        'data': key_types
    })

@app.route('/api/keys')
@admin_required
def get_keys_endpoint():
    """Get activation keys with pagination and filters"""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 25))

    filters = {}
    if 'key_type' in request.args:
        filters['key_type'] = request.args.get('key_type')
    if 'is_active' in request.args:
        filters['is_active'] = request.args.get('is_active') == 'true'
    if 'is_banned' in request.args:
        filters['is_banned'] = request.args.get('is_banned') == 'true'
    if 'customer_name' in request.args:
        filters['customer_name'] = request.args.get('customer_name')
    if 'product_name' in request.args:
        filters['product_name'] = request.args.get('product_name')
    if 'email' in request.args:
        filters['email'] = request.args.get('email')

    result = get_all_keys(page, per_page, filters)
    return jsonify({
        'success': True,
        'data': result
    })

@app.route('/api/keys/generate', methods=['POST'])
@admin_required
def generate_keys():
    """Generate new activation keys"""
    data = request.get_json()
    prefix = data.get('prefix', 'ECP')
    key_type = data.get('key_type', 'month')

    try:
        count = int(data.get('count', 1))
    except ValueError:
        return jsonify({'success': False, 'message': 'Count must be a valid integer'}), 400

    customer_name = data.get('customer_name')
    product_name = data.get('product_name')
    notes = data.get('notes')

    if count > 1000:
        return jsonify({'success': False, 'message': 'Cannot generate more than 1000 keys at once'}), 400

    keys = [generate_key(prefix) for _ in range(count)]
    add_keys_to_db(keys, key_type, customer_name, product_name, notes)

    return jsonify({
        'success': True,
        'message': f'Generated {len(keys)} keys successfully',
        'data': {
            'count': len(keys),
            'keys': keys,
            'key_type': key_type,
            'customer_name': customer_name,
            'product_name': product_name
        }
    })

@app.route('/api/keys/<key_value>/ban', methods=['POST'])
@admin_required
def ban_key_endpoint(key_value):
    """Ban an activation key"""
    success = ban_key(key_value)
    if success:
        return jsonify({'success': True, 'message': 'Key banned successfully'})
    else:
        return jsonify({'success': False, 'message': 'Key not found'}), 404

@app.route('/api/keys/<key_value>/unban', methods=['POST'])
@admin_required
def unban_key_endpoint(key_value):
    """Unban an activation key"""
    success = unban_key(key_value)
    if success:
        return jsonify({'success': True, 'message': 'Key unbanned successfully'})
    else:
        return jsonify({'success': False, 'message': 'Key not found'}), 404

@app.route('/api/keys/<key_value>')
def get_key_details(key_value):
    """Get specific key details"""
    result = check_key_status(key_value)
    if result['status'] == 'success':
        return jsonify({
            'success': True,
            'data': result['data']
        })
    else:
        return jsonify({
            'success': False,
            'message': result['message']
        }), 404

@app.route('/api/activate', methods=['POST'])
def api_activate():
    """Activate a key"""
    data = request.get_json()
    key_value = data.get('key')
    hwid = data.get('hwid')
    machine_id = data.get('machine_id')
    email = data.get('email')

    if not key_value:
        return jsonify({'success': False, 'message': 'Key is required'}), 400

    result = activate_key(key_value, hwid, machine_id, email)
    status_code = 200 if result['status'] == 'success' else 400
    return jsonify({
        'success': result['status'] == 'success',
        'message': result['message']
    }), status_code

@app.route('/api/statistics')
@admin_required
def get_statistics():
    """Get system statistics"""
    stats = get_stats()
    return jsonify({
        'success': True,
        'data': stats
    })

@app.route('/api/customers')
@admin_required
def get_customers_endpoint():
    """Get customer list"""
    customers = get_customers()
    return jsonify({
        'success': True,
        'data': customers
    })

@app.route('/api/products')
@admin_required
def get_products_endpoint():
    """Get product list"""
    products = get_products()
    return jsonify({
        'success': True,
        'data': products
    })

@app.route('/api/export/keys')
@admin_required
def export_keys():
    """Export keys to CSV"""
    import tempfile
    import csv

    # Get all keys
    all_keys = get_all_keys(page=1, per_page=10000)['keys']

    # Create temporary file
    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv', newline='')

    fieldnames = ['key_value', 'key_type', 'is_active', 'is_banned', 'activation_date', 
                  'expiry_date', 'hwid', 'machine_id', 'email', 'customer_name', 
                  'product_name', 'notes', 'created_at']

    writer = csv.DictWriter(temp_file, fieldnames=fieldnames)
    writer.writeheader()

    for key in all_keys:
        writer.writerow(key)

    temp_file.close()

    return send_file(
        temp_file.name,
        as_attachment=True,
        download_name=f'activation_keys_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
        mimetype='text/csv'
    )

@app.route('/')
def index():
    """Serve the admin dashboard"""
    with open('admin_dashboard.html', 'r') as f:
        return f.read()

@app.route('/demo')
def demo():
    """Serve the simple demo page"""
    try:
        with open('demo.html', 'r') as f:
            return f.read()
    except FileNotFoundError:
        return jsonify({'message': 'Demo page not found'}), 404

if __name__ == '__main__':
    print("Starting ECertifPro API Server...")

    # Initialize database
    init_db()

    print("Access the demo at: http://localhost:5000")
    print("Health check: http://localhost:5000/api/health")

    # Start the Flask application
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
