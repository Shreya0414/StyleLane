from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import check_password_hash
import os
import uuid

from aws_config import users_table, inventory_table, shipments_table, sns, SNS_TOPIC_ARN

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_fallback")

# ---------------- LOGIN ---------------- #

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        response = users_table.get_item(Key={"email": email})
        user = response.get("Item")

        if user and check_password_hash(user["password"], password):
            session["user"] = email
            session["role"] = user["role"]

            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            elif user["role"] == "manager":
                return redirect(url_for("manager_dashboard"))
            else:
                return redirect(url_for("supplier_dashboard"))

        return "Invalid Credentials"

    return render_template("login.html")

# ---------------- PUBLIC PAGES ---------------- #

@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

# ---------------- ADMIN ---------------- #

@app.route("/admin")
def admin_dashboard():
    users = users_table.scan().get("Items", [])
    inventory = inventory_table.scan().get("Items", [])
    return render_template(
        "admin_dashboard.html",
        users=users,
        inventory=inventory
    )

# ---------------- MANAGER ---------------- #

@app.route("/manager", methods=["GET", "POST"])
def manager_dashboard():
    if request.method == "POST":
        product_id = request.form["product_id"]
        new_stock = int(request.form["stock"])

        inventory_table.update_item(
            Key={"product_id": product_id},
            UpdateExpression="SET stock = :s",
            ExpressionAttributeValues={":s": new_stock}
        )

        product = inventory_table.get_item(Key={"product_id": product_id})["Item"]
        if product["stock"] < product["threshold"]:
            send_low_stock_alert(product)

    inventory = inventory_table.scan().get("Items", [])
    low_stock = [p for p in inventory if p["stock"] < p["threshold"]]

    return render_template(
        "manager_dashboard.html",
        inventory=inventory,
        low_stock=low_stock
    )

# ---------------- SUPPLIER ---------------- #

@app.route("/supplier", methods=["GET", "POST"])
def supplier_dashboard():
    if request.method == "POST":
        product_id = request.form["product_id"]
        quantity = int(request.form["quantity"])

        inventory_table.update_item(
            Key={"product_id": product_id},
            UpdateExpression="SET stock = stock + :q",
            ExpressionAttributeValues={":q": quantity}
        )

        shipments_table.put_item(
            Item={
                "shipment_id": str(uuid.uuid4()),
                "product_id": product_id,
                "quantity": quantity,
                "status": "Dispatched"
            }
        )

    inventory = inventory_table.scan().get("Items", [])
    shipments = shipments_table.scan().get("Items", [])

    return render_template(
        "supplier_dashboard.html",
        inventory=inventory,
        shipments=shipments
    )

# ---------------- LOGOUT ---------------- #

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------- SNS ---------------- #

def send_low_stock_alert(product):
    message = f"""
LOW STOCK ALERT 🚨

Product: {product['name']}
Current Stock: {product['stock']}
"""
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Message=message,
        Subject="StyleLane Low Stock Alert"
    )

# ---------------- RUN ---------------- #

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
