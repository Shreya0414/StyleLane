from flask import Flask, render_template, request, redirect, url_for, session
import boto3
import uuid
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

# ---------------- APP SETUP ---------------- #

app = Flask(__name__)
app.secret_key = "stylelane_secret_key_here"

# ---------------- AWS CONFIG ---------------- #

REGION = "us-east-1"   # change if needed

dynamodb = boto3.resource("dynamodb", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)

# ---------------- DYNAMODB TABLES ---------------- #
# (Create these tables manually in DynamoDB)

users_table = dynamodb.Table("Users")
inventory_table = dynamodb.Table("Inventory")
shipments_table = dynamodb.Table("Shipments")

# ---------------- SNS TOPIC ---------------- #

SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:XXXXXXXXXXXX:stylelane-alerts"
