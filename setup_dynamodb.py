"""
DynamoDB Table Setup Script for StyleLane
Run this script to create all required DynamoDB tables
"""

import boto3
from botocore.exceptions import ClientError
import os

# Configuration
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
client = boto3.client('dynamodb', region_name=AWS_REGION)


def create_users_table():
    """Create Users table"""
    table_name = 'StyleLane_Users'
    
    try:
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[
                {'AttributeName': 'user_id', 'KeyType': 'HASH'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'user_id', 'AttributeType': 'S'},
                {'AttributeName': 'email', 'AttributeType': 'S'}
            ],
            GlobalSecondaryIndexes=[
                {
                    'IndexName': 'email-index',
                    'KeySchema': [
                        {'AttributeName': 'email', 'KeyType': 'HASH'}
                    ],
                    'Projection': {'ProjectionType': 'ALL'},
                    'ProvisionedThroughput': {
                        'ReadCapacityUnits': 5,
                        'WriteCapacityUnits': 5
                    }
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )
        table.wait_until_exists()
        print(f"Created table: {table_name}")
        return table
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceInUseException':
            print(f"Table {table_name} already exists")
            return dynamodb.Table(table_name)
        raise


def create_products_table():
    """Create Products table"""
    table_name = 'StyleLane_Products'
    
    try:
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[
                {'AttributeName': 'product_id', 'KeyType': 'HASH'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'product_id', 'AttributeType': 'S'},
                {'AttributeName': 'category', 'AttributeType': 'S'}
            ],
            GlobalSecondaryIndexes=[
                {
                    'IndexName': 'category-index',
                    'KeySchema': [
                        {'AttributeName': 'category', 'KeyType': 'HASH'}
                    ],
                    'Projection': {'ProjectionType': 'ALL'},
                    'ProvisionedThroughput': {
                        'ReadCapacityUnits': 5,
                        'WriteCapacityUnits': 5
                    }
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )
        table.wait_until_exists()
        print(f"Created table: {table_name}")
        return table
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceInUseException':
            print(f"Table {table_name} already exists")
            return dynamodb.Table(table_name)
        raise


def create_shipments_table():
    """Create Shipments table"""
    table_name = 'StyleLane_Shipments'
    
    try:
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[
                {'AttributeName': 'shipment_id', 'KeyType': 'HASH'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'shipment_id', 'AttributeType': 'S'},
                {'AttributeName': 'supplier_id', 'AttributeType': 'S'},
                {'AttributeName': 'status', 'AttributeType': 'S'}
            ],
            GlobalSecondaryIndexes=[
                {
                    'IndexName': 'supplier-index',
                    'KeySchema': [
                        {'AttributeName': 'supplier_id', 'KeyType': 'HASH'}
                    ],
                    'Projection': {'ProjectionType': 'ALL'},
                    'ProvisionedThroughput': {
                        'ReadCapacityUnits': 5,
                        'WriteCapacityUnits': 5
                    }
                },
                {
                    'IndexName': 'status-index',
                    'KeySchema': [
                        {'AttributeName': 'status', 'KeyType': 'HASH'}
                    ],
                    'Projection': {'ProjectionType': 'ALL'},
                    'ProvisionedThroughput': {
                        'ReadCapacityUnits': 5,
                        'WriteCapacityUnits': 5
                    }
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )
        table.wait_until_exists()
        print(f"Created table: {table_name}")
        return table
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceInUseException':
            print(f"Table {table_name} already exists")
            return dynamodb.Table(table_name)
        raise


def create_notifications_table():
    """Create Notifications table"""
    table_name = 'StyleLane_Notifications'
    
    try:
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[
                {'AttributeName': 'notification_id', 'KeyType': 'HASH'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'notification_id', 'AttributeType': 'S'},
                {'AttributeName': 'user_id', 'AttributeType': 'S'}
            ],
            GlobalSecondaryIndexes=[
                {
                    'IndexName': 'user-index',
                    'KeySchema': [
                        {'AttributeName': 'user_id', 'KeyType': 'HASH'}
                    ],
                    'Projection': {'ProjectionType': 'ALL'},
                    'ProvisionedThroughput': {
                        'ReadCapacityUnits': 5,
                        'WriteCapacityUnits': 5
                    }
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )
        table.wait_until_exists()
        print(f"Created table: {table_name}")
        return table
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceInUseException':
            print(f"Table {table_name} already exists")
            return dynamodb.Table(table_name)
        raise


def seed_sample_data():
    """Add sample Zara-style products for demonstration"""
    products_table = dynamodb.Table('StyleLane_Products')
    
    sample_products = [
        {
            'product_id': 'PROD001',
            'name': 'Slim Fit Cotton Shirt',
            'category': 'Shirts',
            'brand': 'Zara',
            'price': '39.99',
            'quantity': 45,
            'sku': 'ZR-SH-001',
            'description': 'Classic slim fit cotton shirt in white'
        },
        {
            'product_id': 'PROD002',
            'name': 'High Waist Straight Jeans',
            'category': 'Pants',
            'brand': 'Zara',
            'price': '59.99',
            'quantity': 8,
            'sku': 'ZR-JN-002',
            'description': 'High waist straight leg jeans in medium blue'
        },
        {
            'product_id': 'PROD003',
            'name': 'Oversized Wool Blazer',
            'category': 'Jackets',
            'brand': 'Zara',
            'price': '129.99',
            'quantity': 12,
            'sku': 'ZR-BL-003',
            'description': 'Oversized double-breasted wool blazer'
        },
        {
            'product_id': 'PROD004',
            'name': 'Leather Ankle Boots',
            'category': 'Shoes',
            'brand': 'Zara',
            'price': '89.99',
            'quantity': 5,
            'sku': 'ZR-BT-004',
            'description': 'Black leather ankle boots with block heel'
        },
        {
            'product_id': 'PROD005',
            'name': 'Cashmere Blend Sweater',
            'category': 'Knitwear',
            'brand': 'Zara',
            'price': '79.99',
            'quantity': 22,
            'sku': 'ZR-SW-005',
            'description': 'Soft cashmere blend crew neck sweater'
        },
        {
            'product_id': 'PROD006',
            'name': 'Pleated Midi Skirt',
            'category': 'Skirts',
            'brand': 'Zara',
            'price': '49.99',
            'quantity': 3,
            'sku': 'ZR-SK-006',
            'description': 'Elegant pleated midi skirt in navy'
        },
        {
            'product_id': 'PROD007',
            'name': 'Structured Tote Bag',
            'category': 'Accessories',
            'brand': 'Zara',
            'price': '69.99',
            'quantity': 15,
            'sku': 'ZR-BG-007',
            'description': 'Large structured tote bag in tan leather'
        },
        {
            'product_id': 'PROD008',
            'name': 'Floral Print Maxi Dress',
            'category': 'Dresses',
            'brand': 'Zara',
            'price': '89.99',
            'quantity': 7,
            'sku': 'ZR-DR-008',
            'description': 'Flowing floral print maxi dress'
        }
    ]
    
    for product in sample_products:
        try:
            products_table.put_item(Item=product)
            print(f"Added product: {product['name']}")
        except ClientError as e:
            print(f"Error adding product: {e}")


def main():
    """Main setup function"""
    print("=" * 50)
    print("StyleLane DynamoDB Setup")
    print("=" * 50)
    
    print("\n1. Creating Users table...")
    create_users_table()
    
    print("\n2. Creating Products table...")
    create_products_table()
    
    print("\n3. Creating Shipments table...")
    create_shipments_table()
    
    print("\n4. Creating Notifications table...")
    create_notifications_table()
    
    print("\n5. Seeding sample product data...")
    seed_sample_data()
    
    print("\n" + "=" * 50)
    print("Setup Complete!")
    print("=" * 50)


if __name__ == '__main__':
    main()
