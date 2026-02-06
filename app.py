

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
from functools import wraps
import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import uuid
import csv
import io
import logging
import tempfile

# ==================== APP INITIALIZATION ====================

app = Flask(__name__)

# Configuration
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-this')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# AWS Configuration
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')

# DynamoDB Tables
USERS_TABLE = os.environ.get('USERS_TABLE', 'StyleLane_Users')
PRODUCTS_TABLE = os.environ.get('PRODUCTS_TABLE', 'StyleLane_Products')
SHIPMENTS_TABLE = os.environ.get('SHIPMENTS_TABLE', 'StyleLane_Shipments')
NOTIFICATIONS_TABLE = os.environ.get('NOTIFICATIONS_TABLE', 'StyleLane_Notifications')

# SNS Topics (Optional)
LOW_STOCK_TOPIC = os.environ.get('LOW_STOCK_TOPIC', None)
SHIPMENT_TOPIC = os.environ.get('SHIPMENT_TOPIC', None)

# Business Logic
LOW_STOCK_THRESHOLD = int(os.environ.get('LOW_STOCK_THRESHOLD', '10'))

# AWS Clients
try:
    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
    sns = boto3.client('sns', region_name=AWS_REGION)
except Exception as e:
    print(f"⚠️  AWS Connection Error: {str(e)}")
    print("ℹ️  Make sure your AWS credentials are configured")
    print("   Run: aws configure")

# ==================== LOGGING (Windows Compatible) ====================

# Use temp directory for logs on Windows
log_dir = os.path.join(tempfile.gettempdir(), 'stylelane_logs')
if not os.path.exists(log_dir):
    os.makedirs(log_dir, exist_ok=True)

log_file = os.path.join(log_dir, 'stylelane.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

app.logger.setLevel(logging.INFO)
app.logger.info(f'StyleLane startup (Windows Dev Mode)')
app.logger.info(f'Logs location: {log_file}')

# ==================== HELPER FUNCTIONS ====================

def get_table(table_name):
    """Get DynamoDB table resource"""
    return dynamodb.Table(table_name)

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    """Decorator to require specific roles"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ==================== HEALTH CHECK ====================

@app.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        table = get_table(USERS_TABLE)
        table.table_status
        return jsonify({'status': 'healthy', 'logs': log_file}), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 503

# ==================== PUBLIC ROUTES ====================

@app.route('/')
def index():
    """Landing page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        app.logger.info(f"Login attempt for email: {email}")
        
        if not email or not password:
            flash('Email and password are required.', 'danger')
            return render_template('login.html')
        
        try:
            table = get_table(USERS_TABLE)
            response = table.query(
                IndexName='email-index',
                KeyConditionExpression=Key('email').eq(email)
            )
            
            if response['Items']:
                user = response['Items'][0]
                
                if user.get('status') != 'active':
                    flash('Your account is inactive.', 'danger')
                    return render_template('login.html')
                
                if check_password_hash(user['password'], password):
                    session.permanent = True
                    session['user_id'] = user['user_id']
                    session['email'] = user['email']
                    session['name'] = user['name']
                    session['role'] = user['role']
                    
                    flash(f'Welcome back, {user["name"]}!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid email or password.', 'danger')
            else:
                flash('Invalid email or password.', 'danger')
                
        except ClientError as e:
            app.logger.error(f"Login error (AWS): {str(e)}")
            flash('Login failed. Please check your AWS connection.', 'danger')
        except Exception as e:
            app.logger.error(f"Login error (General): {str(e)}", exc_info=True)
            flash('Login failed. An unexpected error occurred.', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'store_manager')
        
        if not all([name, email, password]):
            flash('All fields are required.', 'danger')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
            return render_template('register.html')
        
        try:
            table = get_table(USERS_TABLE)
            
            response = table.query(
                IndexName='email-index',
                KeyConditionExpression=Key('email').eq(email)
            )
            
            if response['Items']:
                flash('Email already registered.', 'warning')
                return render_template('register.html')
            
            user_id = str(uuid.uuid4())
            password_hash = generate_password_hash(password)
            
            table.put_item(Item={
                'user_id': user_id,
                'name': name,
                'email': email,
                'password': password_hash,
                'role': role,
                'created_at': datetime.now().isoformat(),
                'status': 'active'
            })
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except ClientError as e:
            app.logger.error(f"Registration error (AWS): {str(e)}")
            flash('Registration failed. Please check your AWS connection.', 'danger')
        except Exception as e:
            app.logger.error(f"Registration error (General): {str(e)}", exc_info=True)
            flash('Registration failed. An unexpected error occurred.', 'danger')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# ==================== DASHBOARD ROUTES ====================

@app.route('/dashboard')
@login_required
def dashboard():
    """Role-based dashboard router"""
    role = session.get('role')
    
    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif role == 'store_manager':
        return redirect(url_for('manager_dashboard'))
    elif role == 'supplier':
        return redirect(url_for('supplier_dashboard'))
    else:
        return render_template('dashboard.html')

@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    """Admin dashboard"""
    try:
        products_table = get_table(PRODUCTS_TABLE)
        products = products_table.scan().get('Items', [])
        
        shipments_table = get_table(SHIPMENTS_TABLE)
        shipments = shipments_table.scan().get('Items', [])
        
        users_table = get_table(USERS_TABLE)
        users = users_table.scan().get('Items', [])
        
        stats = {
            'total_products': len(products),
            'low_stock_count': len([p for p in products if int(p.get('quantity', 0)) < LOW_STOCK_THRESHOLD]),
            'pending_shipments': len([s for s in shipments if s.get('status') == 'pending']),
            'total_users': len(users)
        }
        
        return render_template(
            'admin/dashboard.html',
            stats=stats,
            products=sorted(products, key=lambda x: int(x.get('quantity', 0)))[:10],
            shipments=sorted(shipments, key=lambda x: x.get('requested_at', ''), reverse=True)[:10],
            users=users
        )
    except Exception as e:
        app.logger.error(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard. Check AWS connection.', 'danger')
        return render_template('admin/dashboard.html', stats={}, products=[], shipments=[], users=[])

@app.route('/manager/dashboard')
@login_required
@role_required('store_manager')
def manager_dashboard():
    """Store Manager dashboard"""
    try:
        products_table = get_table(PRODUCTS_TABLE)
        products = products_table.scan().get('Items', [])
        
        shipments_table = get_table(SHIPMENTS_TABLE)
        shipments = shipments_table.scan().get('Items', [])
        
        low_stock = [p for p in products if int(p.get('quantity', 0)) < LOW_STOCK_THRESHOLD]
        
        stats = {
            'total_products': len(products),
            'low_stock_count': len(low_stock),
            'incoming_shipments': len([s for s in shipments if s.get('status') in ['pending', 'shipped']])
        }
        
        return render_template(
            'manager/dashboard.html',
            stats=stats,
            products=products,
            low_stock=low_stock,
            shipments=sorted(shipments, key=lambda x: x.get('requested_at', ''), reverse=True)[:5]
        )
    except Exception as e:
        app.logger.error(f"Manager dashboard error: {str(e)}")
        flash('Error loading dashboard.', 'danger')
        return render_template('manager/dashboard.html', stats={}, products=[], low_stock=[], shipments=[])

@app.route('/supplier/dashboard')
@login_required
@role_required('supplier')
def supplier_dashboard():
    """Supplier dashboard"""
    try:
        shipments_table = get_table(SHIPMENTS_TABLE)
        
        response = shipments_table.query(
            IndexName='supplier-index',
            KeyConditionExpression=Key('supplier_id').eq(session['user_id'])
        )
        
        shipments = response.get('Items', [])
        
        stats = {
            'pending_requests': len([s for s in shipments if s.get('status') == 'pending']),
            'active_shipments': len([s for s in shipments if s.get('status') == 'shipped']),
            'completed_shipments': len([s for s in shipments if s.get('status') in ['delivered', 'received']])
        }
        
        return render_template(
            'supplier/dashboard.html',
            stats=stats,
            pending_requests=[s for s in shipments if s.get('status') == 'pending'],
            active_shipments=[s for s in shipments if s.get('status') == 'shipped'],
            shipments=sorted(shipments, key=lambda x: x.get('requested_at', ''), reverse=True)
        )
    except Exception as e:
        app.logger.error(f"Supplier dashboard error: {str(e)}")
        flash('Error loading dashboard.', 'danger')
        return render_template('supplier/dashboard.html', stats={}, pending_requests=[], active_shipments=[], shipments=[])

# ==================== PRODUCT ROUTES ====================

@app.route('/products')
@login_required
def products():
    """View all products"""
    try:
        table = get_table(PRODUCTS_TABLE)
        products = table.scan().get('Items', [])
        return render_template('products/list.html', products=products)
    except Exception as e:
        app.logger.error(f"Products error: {str(e)}")
        flash('Error loading products.', 'danger')
        return render_template('products/list.html', products=[])

@app.route('/products/add', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'store_manager')
def add_product():
    """Add new product"""
    if request.method == 'POST':
        try:
            table = get_table(PRODUCTS_TABLE)
            
            product = {
                'product_id': str(uuid.uuid4()),
                'name': request.form.get('name').strip(),
                'category': request.form.get('category'),
                'brand': request.form.get('brand').strip(),
                'price': request.form.get('price'),
                'quantity': int(request.form.get('quantity')),
                'sku': request.form.get('sku').strip(),
                'description': request.form.get('description', '').strip(),
                'created_at': datetime.now().isoformat(),
                'updated_by': session['user_id']
            }
            
            table.put_item(Item=product)
            flash('Product added successfully!', 'success')
            return redirect(url_for('products'))
            
        except Exception as e:
            app.logger.error(f"Add product error: {str(e)}")
            flash('Error adding product.', 'danger')
    
    return render_template('products/add.html')

@app.route('/products/update/<product_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'store_manager')
def update_product(product_id):
    """Update product"""
    try:
        table = get_table(PRODUCTS_TABLE)
        
        if request.method == 'POST':
            new_quantity = int(request.form.get('quantity', 0))
            
            table.update_item(
                Key={'product_id': product_id},
                UpdateExpression='SET quantity = :q, updated_at = :t',
                ExpressionAttributeValues={
                    ':q': new_quantity,
                    ':t': datetime.now().isoformat()
                }
            )
            
            flash('Stock updated successfully!', 'success')
            return redirect(url_for('products'))
        
        response = table.get_item(Key={'product_id': product_id})
        product = response.get('Item')
        
        if not product:
            flash('Product not found.', 'danger')
            return redirect(url_for('products'))
        
        return render_template('products/update.html', product=product)
        
    except Exception as e:
        app.logger.error(f"Update product error: {str(e)}")
        flash('Error updating product.', 'danger')
        return redirect(url_for('products'))

# ==================== SHIPMENT ROUTES ====================

@app.route('/shipments')
@login_required
def shipments():
    """View all shipments"""
    try:
        table = get_table(SHIPMENTS_TABLE)
        
        if session['role'] == 'supplier':
            response = table.query(
                IndexName='supplier-index',
                KeyConditionExpression=Key('supplier_id').eq(session['user_id'])
            )
        else:
            response = table.scan()
        
        shipments = response.get('Items', [])
        return render_template('shipments/list.html', shipments=shipments)
    except Exception as e:
        app.logger.error(f"Shipments error: {str(e)}")
        flash('Error loading shipments.', 'danger')
        return render_template('shipments/list.html', shipments=[])

@app.route('/shipments/request', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'store_manager')
def request_shipment():
    """Create restock request"""
    if request.method == 'POST':
        try:
            product_id = request.form.get('product_id')
            quantity = int(request.form.get('quantity', 0))
            
            products_table = get_table(PRODUCTS_TABLE)
            product = products_table.get_item(Key={'product_id': product_id}).get('Item')
            
            users_table = get_table(USERS_TABLE)
            suppliers = users_table.scan(
                FilterExpression=Attr('role').eq('supplier') & Attr('status').eq('active')
            ).get('Items', [])
            
            if not suppliers:
                flash('No suppliers available.', 'warning')
                return redirect(url_for('products'))
            
            supplier = suppliers[0]
            
            shipment = {
                'shipment_id': str(uuid.uuid4()),
                'product_id': product_id,
                'product_name': product.get('name'),
                'quantity': quantity,
                'supplier_id': supplier['user_id'],
                'supplier_name': supplier['name'],
                'status': 'pending',
                'requested_by': session['user_id'],
                'requested_at': datetime.now().isoformat()
            }
            
            shipments_table = get_table(SHIPMENTS_TABLE)
            shipments_table.put_item(Item=shipment)
            
            flash('Restock request sent!', 'success')
            return redirect(url_for('shipments'))
            
        except Exception as e:
            app.logger.error(f"Request shipment error: {str(e)}")
            flash('Error creating shipment.', 'danger')
    
    try:
        products_table = get_table(PRODUCTS_TABLE)
        products = products_table.scan().get('Items', [])
        low_stock = [p for p in products if int(p.get('quantity', 0)) < LOW_STOCK_THRESHOLD]
        return render_template('shipments/request.html', products=low_stock)
    except:
        return render_template('shipments/request.html', products=[])

@app.route('/shipments/update/<shipment_id>', methods=['POST'])
@login_required
@role_required('supplier')
def update_shipment(shipment_id):
    """Update shipment status"""
    try:
        new_status = request.form.get('status')
        tracking_number = request.form.get('tracking_number', '').strip()
        
        table = get_table(SHIPMENTS_TABLE)
        
        update_expr = 'SET #s = :s, updated_at = :t'
        expr_values = {':s': new_status, ':t': datetime.now().isoformat()}
        
        if tracking_number:
            update_expr += ', tracking_number = :tn'
            expr_values[':tn'] = tracking_number
        
        table.update_item(
            Key={'shipment_id': shipment_id},
            UpdateExpression=update_expr,
            ExpressionAttributeNames={'#s': 'status'},
            ExpressionAttributeValues=expr_values
        )
        
        flash(f'Shipment updated to {new_status}!', 'success')
        
    except Exception as e:
        app.logger.error(f"Update shipment error: {str(e)}")
        flash('Error updating shipment.', 'danger')
    
    return redirect(url_for('supplier_dashboard'))

@app.route('/shipments/receive/<shipment_id>', methods=['POST'])
@login_required
@role_required('store_manager', 'admin')
def receive_shipment(shipment_id):
    """Mark shipment as received"""
    try:
        shipments_table = get_table(SHIPMENTS_TABLE)
        products_table = get_table(PRODUCTS_TABLE)
        
        shipment = shipments_table.get_item(Key={'shipment_id': shipment_id}).get('Item')
        
        shipments_table.update_item(
            Key={'shipment_id': shipment_id},
            UpdateExpression='SET #s = :s, received_at = :r',
            ExpressionAttributeNames={'#s': 'status'},
            ExpressionAttributeValues={
                ':s': 'received',
                ':r': datetime.now().isoformat()
            }
        )
        
        product_id = shipment['product_id']
        quantity_received = int(shipment['quantity'])
        
        product = products_table.get_item(Key={'product_id': product_id}).get('Item', {})
        current_quantity = int(product.get('quantity', 0))
        
        products_table.update_item(
            Key={'product_id': product_id},
            UpdateExpression='SET quantity = :q, updated_at = :t',
            ExpressionAttributeValues={
                ':q': current_quantity + quantity_received,
                ':t': datetime.now().isoformat()
            }
        )
        
        flash(f'Shipment received! Inventory updated by {quantity_received} units.', 'success')
        
    except Exception as e:
        app.logger.error(f"Receive shipment error: {str(e)}")
        flash('Error receiving shipment.', 'danger')
    
    return redirect(url_for('manager_dashboard'))

# ==================== ADMIN ROUTES ====================

@app.route('/admin/users')
@login_required
@role_required('admin')
def manage_users():
    """Manage users"""
    try:
        table = get_table(USERS_TABLE)
        users = table.scan().get('Items', [])
        for user in users:
            user.pop('password', None)
        return render_template('admin/users.html', users=users)
    except Exception as e:
        app.logger.error(f"Manage users error: {str(e)}")
        flash('Error loading users.', 'danger')
        return render_template('admin/users.html', users=[])

@app.route('/admin/users/update/<user_id>', methods=['POST'])
@login_required
@role_required('admin')
def update_user_role(user_id):
    """Update user role"""
    try:
        new_role = request.form.get('role')
        
        table = get_table(USERS_TABLE)
        table.update_item(
            Key={'user_id': user_id},
            UpdateExpression='SET #r = :r, updated_at = :t',
            ExpressionAttributeNames={'#r': 'role'},
            ExpressionAttributeValues={
                ':r': new_role,
                ':t': datetime.now().isoformat()
            }
        )
        
        flash('User role updated!', 'success')
        
    except Exception as e:
        app.logger.error(f"Update user error: {str(e)}")
        flash('Error updating user.', 'danger')
    
    return redirect(url_for('manage_users'))

@app.route('/admin/export/<data_type>')
@login_required
@role_required('admin')
def export_data(data_type):
    """Export data to CSV"""
    try:
        if data_type == 'products':
            table = get_table(PRODUCTS_TABLE)
            items = table.scan().get('Items', [])
            filename = f'products_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            fieldnames = ['product_id', 'name', 'category', 'brand', 'price', 'quantity', 'sku']
        elif data_type == 'shipments':
            table = get_table(SHIPMENTS_TABLE)
            items = table.scan().get('Items', [])
            filename = f'shipments_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            fieldnames = ['shipment_id', 'product_name', 'quantity', 'status', 'supplier_name', 'requested_at']
        elif data_type == 'users':
            table = get_table(USERS_TABLE)
            items = table.scan().get('Items', [])
            for item in items:
                item.pop('password', None)
            filename = f'users_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            fieldnames = ['user_id', 'name', 'email', 'role', 'status', 'created_at']
        else:
            flash('Invalid export type.', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(items)
        
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
    except Exception as e:
        app.logger.error(f"Export error: {str(e)}")
        flash('Error exporting data.', 'danger')
        return redirect(url_for('admin_dashboard'))

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def server_error(e):
    app.logger.error(f"Server error: {str(e)}", exc_info=True)
    return render_template('errors/500.html'), 500

# ==================== MAIN ====================

if __name__ == '__main__':
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    host = os.environ.get('FLASK_HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', 5000))

    print("=" * 70)
    print("  STYLELANE")
    print("=" * 70)
    print(f"  🌐 URL: http://{host}:{port}")
    print("=" * 70)

    app.run(host=host, port=port, debug=debug)