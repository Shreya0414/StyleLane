# StyleLane - AWS Deployment Guide

## Prerequisites

1. AWS Account with appropriate permissions
2. AWS CLI configured locally
3. Python 3.9+ installed

## Step 1: AWS Account Setup

1. Log in to AWS Management Console
2. Ensure you have access to EC2, DynamoDB, SNS, and IAM services

## Step 2: IAM Role Setup

### Create IAM Role for EC2

1. Go to IAM Console > Roles > Create Role
2. Select "AWS Service" > "EC2"
3. Attach the following policies:
   - `AmazonDynamoDBFullAccess`
   - `AmazonSNSFullAccess`
4. Name the role: `StyleLane-EC2-Role`

### Create IAM User for Local Development (Optional)

1. Go to IAM Console > Users > Create User
2. Attach the same policies
3. Generate Access Keys for CLI usage

## Step 3: DynamoDB Setup

Run the setup script locally or on EC2:

```bash
# Set AWS credentials (if not using IAM role)
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=us-east-1

# Run the setup script
python setup_dynamodb.py
```

This creates the following tables:
- `StyleLane_Users`
- `StyleLane_Products`
- `StyleLane_Shipments`
- `StyleLane_Notifications`

## Step 4: SNS Setup

Run the SNS setup script:

```bash
python setup_sns.py
```

This creates:
- `StyleLane_LowStockAlerts` topic
- `StyleLane_ShipmentUpdates` topic

### Subscribe Emails to Topics

```bash
python setup_sns.py --subscribe <topic_arn> <email>
```

**Important:** Check your email and confirm the subscription.

## Step 5: EC2 Instance Setup

### Launch EC2 Instance

1. Go to EC2 Console > Launch Instance
2. Configuration:
   - **AMI:** Amazon Linux 2023 or Ubuntu 22.04
   - **Instance Type:** t2.micro (free tier) or t2.small
   - **Key Pair:** Create or select existing
   - **IAM Role:** Select `StyleLane-EC2-Role`

### Security Group Configuration

Create/configure security group with these inbound rules:

| Type  | Port | Source    |
|-------|------|-----------|
| SSH   | 22   | Your IP   |
| HTTP  | 80   | 0.0.0.0/0 |
| Custom| 5000 | 0.0.0.0/0 |

## Step 6: Deploy Application to EC2

### Connect to EC2

```bash
ssh -i your-key.pem ec2-user@your-ec2-public-ip
```

### Install Dependencies (Amazon Linux 2023)

```bash
# Update system
sudo dnf update -y

# Install Python and pip
sudo dnf install python3 python3-pip -y

# Install git
sudo dnf install git -y
```

### Install Dependencies (Ubuntu)

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv git -y
```

### Upload and Setup Application

```bash
# Create app directory
mkdir -p /home/ec2-user/stylelane
cd /home/ec2-user/stylelane

# Upload files (use scp from local machine)
# scp -i your-key.pem -r ./stylelane/* ec2-user@your-ec2-ip:/home/ec2-user/stylelane/

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export SECRET_KEY=your-secret-key-here
export AWS_REGION=us-east-1
export LOW_STOCK_TOPIC=arn:aws:sns:us-east-1:YOUR_ACCOUNT:StyleLane_LowStockAlerts
export SHIPMENT_TOPIC=arn:aws:sns:us-east-1:YOUR_ACCOUNT:StyleLane_ShipmentUpdates
```

### Run the Application

#### Development Mode

```bash
python app.py
```

#### Production Mode (with Gunicorn)

```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Run as a Service (Recommended)

Create systemd service file:

```bash
sudo nano /etc/systemd/system/stylelane.service
```

Add the following content:

```ini
[Unit]
Description=StyleLane Flask Application
After=network.target

[Service]
User=ec2-user
WorkingDirectory=/home/ec2-user/stylelane
Environment="PATH=/home/ec2-user/stylelane/venv/bin"
Environment="SECRET_KEY=your-secret-key"
Environment="AWS_REGION=us-east-1"
Environment="LOW_STOCK_TOPIC=arn:aws:sns:us-east-1:YOUR_ACCOUNT:StyleLane_LowStockAlerts"
Environment="SHIPMENT_TOPIC=arn:aws:sns:us-east-1:YOUR_ACCOUNT:StyleLane_ShipmentUpdates"
ExecStart=/home/ec2-user/stylelane/venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable stylelane
sudo systemctl start stylelane
sudo systemctl status stylelane
```

## Step 7: Configure Nginx (Optional - for Production)

```bash
sudo dnf install nginx -y  # Amazon Linux
# or
sudo apt install nginx -y  # Ubuntu

sudo nano /etc/nginx/conf.d/stylelane.conf
```

Add configuration:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Restart Nginx:

```bash
sudo systemctl restart nginx
```

## Step 8: Testing

1. Access your application: `http://your-ec2-public-ip:5000`
2. Register a new user
3. Test different roles (Admin, Store Manager, Supplier)
4. Verify DynamoDB data in AWS Console
5. Test SNS notifications

## Environment Variables Reference

| Variable | Description | Required |
|----------|-------------|----------|
| SECRET_KEY | Flask secret key for sessions | Yes |
| AWS_REGION | AWS region (default: us-east-1) | No |
| USERS_TABLE | DynamoDB users table name | No |
| PRODUCTS_TABLE | DynamoDB products table name | No |
| SHIPMENTS_TABLE | DynamoDB shipments table name | No |
| LOW_STOCK_TOPIC | SNS topic ARN for low stock alerts | No |
| SHIPMENT_TOPIC | SNS topic ARN for shipment updates | No |

## Troubleshooting

### Common Issues

1. **DynamoDB Access Denied**
   - Verify IAM role is attached to EC2
   - Check IAM policies include DynamoDB permissions

2. **SNS Not Sending Emails**
   - Confirm email subscription is confirmed
   - Check topic ARN is correct in environment variables

3. **Application Not Accessible**
   - Verify security group allows inbound traffic on port 5000
   - Check application is running: `sudo systemctl status stylelane`

### View Application Logs

```bash
sudo journalctl -u stylelane -f
```

## Security Recommendations

1. Use HTTPS with SSL certificate (AWS Certificate Manager + Load Balancer)
2. Store secrets in AWS Secrets Manager
3. Enable VPC for private networking
4. Use AWS WAF for web application firewall
5. Enable CloudWatch for monitoring and alerting
