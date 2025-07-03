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
import atexit

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'hfXFDFdfdfdf5dg52fgfgfdkVCGFgkdf5')
CORS(app)  # Enable CORS for all routes

# تحسين مسار قاعدة البيانات لتعمل مع Render
DATABASE = os.path.join(os.getcwd(), 'instance', 'activation_keys.db')

# إنشاء مجلد instance إذا لم يكن موجودًا
os.makedirs(os.path.join(os.getcwd(), 'instance'), exist_ok=True)

# إدارة اتصالات قاعدة البيانات
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# إغلاق جميع اتصالات قاعدة البيانات عند إنهاء التطبيق
def close_db_connections():
    conn = get_db_connection()
    conn.close()

atexit.register(close_db_connections)

# Database initialization with error handling
def init_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Enable foreign key constraints
        cursor.execute('PRAGMA foreign_keys = ON')

        # Create tables if they don't exist with error handling
        tables = {
            'activation_keys': '''
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
            ''',
            'admin_users': '''
            CREATE TABLE IF NOT EXISTS admin_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                api_key TEXT UNIQUE NULL,
                is_superadmin BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL
            )
            ''',
            'key_types': '''
            CREATE TABLE IF NOT EXISTS key_types (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                duration_days INTEGER NOT NULL,
                description TEXT NULL,
                price REAL NULL,
                is_available BOOLEAN DEFAULT 1
            )
            ''',
            'products': '''
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            )
            '''
        }

        for table_name, table_sql in tables.items():
            try:
                cursor.execute(table_sql)
            except sqlite3.Error as e:
                print(f"Error creating table {table_name}: {e}")
                # Attempt to recover by dropping and recreating the table
                if "already exists" in str(e):
                    cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
                    cursor.execute(table_sql)
                    print(f"Recovered table {table_name} by recreating it")

        # Insert default key types if they don't exist
        default_key_types = [
            ('7day', 7, '7 Day License', 9.99),
            ('month', 30, '1 Month License', 29.99),
            ('6month', 180, '6 Month License', 149.99),
            ('1year', 365, '1 Year License', 249.99),
            ('lifetime', 36500, 'Lifetime License', 499.99)
        ]

        for key_type in default_key_types:
            try:
                cursor.execute('''
                INSERT OR IGNORE INTO key_types (name, duration_days, description, price)
                VALUES (?, ?, ?, ?)
                ''', key_type)
            except sqlite3.Error as e:
                print(f"Error inserting key type {key_type[0]}: {e}")

        # Create default admin if none exists
        cursor.execute('SELECT COUNT(*) FROM admin_users')
        if cursor.fetchone()[0] == 0:
            password_hash = generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'admin'))
            api_key = os.environ.get('ADMIN_API_KEY', 'bc3eabae-7ee2-40fa-b19b-53f1bfd3c8ad')
            try:
                cursor.execute('''
                INSERT INTO admin_users (username, password_hash, api_key, is_superadmin) 
                VALUES (?, ?, ?, ?)
                ''', ('admin', password_hash, api_key, 1))
            except sqlite3.Error as e:
                print(f"Error creating default admin: {e}")

        conn.commit()
    except sqlite3.Error as e:
        print(f"Database initialization failed: {e}")
        # Attempt to recover by recreating the database file
        try:
            if os.path.exists(DATABASE):
                os.remove(DATABASE)
            init_db()  # Recursive call to try again
        except Exception as e:
            print(f"Critical error: Could not initialize database: {e}")
            raise
    finally:
        conn.close()

# Generate a secure API key
def generate_api_key():
    return str(uuid.uuid4())

# Admin user management
def create_admin(username, password, is_superadmin=False):
    conn = get_db_connection()
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
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    SELECT password_hash, api_key FROM admin_users 
    WHERE username = ?
    ''', (username,))
    result = cursor.fetchone()
    conn.close()

    if result and check_password_hash(result['password_hash'], password):
        # Update last login time
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
        UPDATE admin_users 
        SET last_login = CURRENT_TIMESTAMP 
        WHERE username = ?
        ''', (username,))
        conn.commit()
        conn.close()
        return result['api_key']  # Return API key
    return None

def get_admin_by_api_key(api_key):
    conn = get_db_connection()
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
        if not admin_info or not admin_info['is_superadmin']:
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
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    SELECT duration_days FROM key_types WHERE name = ?
    ''', (key_type,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return datetime.now() + timedelta(days=result['duration_days'])
    return None

# Database operations
def add_keys_to_db(keys, key_type, customer_name=None, product_name=None, notes=None):
    conn = get_db_connection()
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
    conn = get_db_connection()
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
    conn = get_db_connection()
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
    conn = get_db_connection()
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

    is_banned = result['is_banned']
    is_active = result['is_active']
    activation_date = result['activation_date']
    key_type = result['key_type']

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
    conn = get_db_connection()
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
    activation_date = parse_datetime(result['activation_date'])
    expiry_date = parse_datetime(result['expiry_date'])
    created_at = parse_datetime(result['created_at'])

    # Check if key is valid
    is_valid = (
        not bool(result['is_banned']) and  # not banned
        bool(result['is_active']) and      # is active
        (not expiry_date or expiry_date > datetime.now())  # not expired
    )

    key_data = {
        'key': result['key_value'],
        'type': result['key_type'],
        'is_active': bool(result['is_active']),
        'is_banned': bool(result['is_banned']),
        'activation_date': activation_date.isoformat() if activation_date else None,
        'expiry_date': expiry_date.isoformat() if expiry_date else None,
        'hwid': result['hwid'],
        'machine_id': result['machine_id'],
        'email': result['email'],
        'customer_name': result['customer_name'],
        'product_name': result['product_name'],
        'notes': result['notes'],
        'created_at': created_at.isoformat() if created_at else None,
        'is_valid': is_valid
    }

    return {'status': 'success', 'data': key_data}

def get_all_keys(page=1, per_page=100, filters=None):
    conn = get_db_connection()
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
            'key_value': result['key_value'],
            'key_type': result['key_type'],
            'is_active': bool(result['is_active']),
            'is_banned': bool(result['is_banned']),
            'activation_date': result['activation_date'],
            'expiry_date': result['expiry_date'],
            'hwid': result['hwid'],
            'machine_id': result['machine_id'],
            'email': result['email'],
            'customer_name': result['customer_name'],
            'product_name': result['product_name'],
            'notes': result['notes'],
            'created_at': result['created_at']
        })

    return {
        'keys': keys,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page
    }

def get_key_types():
    conn = get_db_connection()
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
            'name': result['name'],
            'duration_days': result['duration_days'],
            'description': result['description'],
            'price': result['price'],
            'is_available': bool(result['is_available'])
        })

    return key_types

def get_customers():
    conn = get_db_connection()
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
            'name': result['name'],
            'email': result['email'],
            'total_keys': result['total_keys'],
            'active_keys': result['active_keys'],
            'activated_keys': result['activated_keys']
        })

    return customers

def get_products():
    conn = get_db_connection()
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
        key_types = result['key_types'].split(',') if result['key_types'] else []
        products.append({
            'name': result['name'],
            'total_keys': result['total_keys'],
            'active_keys': result['active_keys'],
            'activated_keys': result['activated_keys'],
            'key_types': key_types
        })

    return products

def get_stats():
    conn = get_db_connection()
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
    key_types_dist = {row['key_type']: row['COUNT(*)'] for row in cursor.fetchall()}

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
        'timestamp': datetime.now().isoformat(),
        'database_path': DATABASE,
        'database_exists': os.path.exists(DATABASE)
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
    try:
        with open('admin_dashboard.html', 'r') as f:
            return f.read()
    except FileNotFoundError:
        return jsonify({
            'success': False,
            'message': 'Admin dashboard not found',
            'hint': 'Make sure admin_dashboard.html exists in the root directory'
        }), 404

@app.route('/demo')
def demo():
    """Serve the simple demo page"""
    try:
        with open('demo.html', 'r') as f:
            return f.read()
    except FileNotFoundError:
        return jsonify({
            'success': False,
            'message': 'Demo page not found',
            'hint': 'Make sure demo.html exists in the root directory'
        }), 404

if __name__ == '__main__':
    print("Starting ECertifPro API Server...")
    print(f"Database path: {DATABASE}")

    # Initialize database with error handling
    try:
        init_db()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Failed to initialize database: {e}")
        raise

    print("Access the demo at: http://localhost:5000")
    print("Health check: http://localhost:5000/api/health")

    # Start the Flask application
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
