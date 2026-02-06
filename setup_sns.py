"""
StyleLane - Fashion Retail Inventory Management System
Flask Application with AWS Integration (Troven Lab Ready)
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
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

# ==================== APP CONFIG ====================

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'stylelane-secret')

AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')

USERS_TABLE = os.environ.get('USERS_TABLE', 'StyleLane_Users')
PRODUCTS_TABLE = os.environ.get('PRODUCTS_TABLE', 'StyleLane_Products')
SHIPMENTS_TABLE = os.environ.get('SHIPMENTS_TABLE', 'StyleLane_Shipments')

LOW_STOCK_TOPIC = os.environ.get('LOW_STOCK_TOPIC')
SHIPMENT_TOPIC = os.environ.get('SHIPMENT_TOPIC')

LOW_STOCK_THRESHOLD = int(os.environ.get('LOW_STOCK_THRESHOLD', 10))

dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
sns = boto3.client('sns', region_name=AWS_REGION)

# ==================== HELPERS ====================

def get_table(name):
    return dynamodb.Table(name)

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Login required', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if session.get('role') not in roles:
                flash('Access denied', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ==================== AUTH ====================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        table = get_table(USERS_TABLE)

        try:
            response = table.query(
                IndexName='email-index',
                KeyConditionExpression=Key('email').eq(email)
            )

            if not response['Items']:
                flash('Invalid credentials', 'danger')
                return redirect(url_for('login'))

            user = response['Items'][0]

            if not check_password_hash(user['password'], password):
                flash('Invalid credentials', 'danger')
                return redirect(url_for('login'))

            session.update({
                'user_id': user['user_id'],
                'name': user['name'],
                'email': user['email'],
                'role': user['role']
            })

            return redirect(url_for('dashboard'))

        except ClientError as e:
            flash('Login failed', 'danger')
            print(e)

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        table = get_table(USERS_TABLE)

        email = request.form.get('email')

        existing = table.query(
            IndexName='email-index',
            KeyConditionExpression=Key('email').eq(email)
        )

        if existing['Items']:
            flash('Email already exists', 'warning')
            return redirect(url_for('register'))

        table.put_item(Item={
            'user_id': str(uuid.uuid4()),
            'name': request.form.get('name'),
            'email': email,
            'password': generate_password_hash(request.form.get('password')),
            'role': request.form.get('role', 'store_manager'),
            'created_at': datetime.utcnow().isoformat(),
            'status': 'active'
        })

        flash('Registration successful', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ==================== DASHBOARD ====================

@app.route('/dashboard')
@login_required
def dashboard():
    role = session['role']
    return redirect(url_for(f"{role}_dashboard"))

@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    products = get_table(PRODUCTS_TABLE).scan().get('Items', [])
    shipments = get_table(SHIPMENTS_TABLE).scan().get('Items', [])
    users = get_table(USERS_TABLE).scan().get('Items', [])

    return render_template(
        'admin/dashboard.html',
        stats={
            'total_products': len(products),
            'low_stock': len([p for p in products if int(p['quantity']) < LOW_STOCK_THRESHOLD]),
            'shipments': len(shipments),
            'users': len(users)
        }
    )

# ==================== PRODUCTS ====================

@app.route('/products')
@login_required
def products():
    items = get_table(PRODUCTS_TABLE).scan().get('Items', [])
    return render_template('products/list.html', products=items)

# ==================== SNS ====================

def publish(topic, subject, message):
    if not topic:
        return
    sns.publish(TopicArn=topic, Subject=subject, Message=message)

# ==================== MAIN ====================

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)