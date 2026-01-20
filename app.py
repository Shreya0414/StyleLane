from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = "stylelane_secret_key"

# ---------------- LOCAL DATA (TEMPORARY) ---------------- #

users = {
    "admin@stylelane.com": {"password": "admin123", "role": "admin"},
    "manager@stylelane.com": {"password": "manager123", "role": "manager"},
    "supplier@stylelane.com": {"password": "supplier123", "role": "supplier"}
}

inventory = {
    "ZARA101": {"name": "Zara Denim Jacket", "stock": 25, "threshold": 10},
    "ZARA102": {"name": "Zara Cotton Shirt", "stock": 8, "threshold": 10},
}

shipments = []

# ---------------- ROUTES ---------------- #

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        if email in users and users[email]["password"] == password:
            session["user"] = email
            session["role"] = users[email]["role"]

            if session["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            elif session["role"] == "manager":
                return redirect(url_for("manager_dashboard"))
            else:
                return redirect(url_for("supplier_dashboard"))

        return "Invalid Credentials"

    return render_template("login.html")


# ---------- NEW PUBLIC PAGES ---------- #

@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")


# ---------- DASHBOARDS ---------- #

@app.route("/admin")
def admin_dashboard():
    return render_template("admin_dashboard.html", inventory=inventory, users=users)


@app.route("/manager", methods=["GET", "POST"])
def manager_dashboard():
    if request.method == "POST":
        product_id = request.form["product_id"]
        new_stock = int(request.form["stock"])

        inventory[product_id]["stock"] = new_stock

    low_stock = {
        pid: p for pid, p in inventory.items()
        if p["stock"] < p["threshold"]
    }

    return render_template("manager_dashboard.html",
                           inventory=inventory,
                           low_stock=low_stock)


@app.route("/supplier", methods=["GET", "POST"])
def supplier_dashboard():
    if request.method == "POST":
        product_id = request.form["product_id"]
        quantity = int(request.form["quantity"])

        inventory[product_id]["stock"] += quantity
        shipments.append({
            "product_id": product_id,
            "quantity": quantity,
            "status": "Dispatched"
        })

    return render_template("supplier_dashboard.html",
                           inventory=inventory,
                           shipments=shipments)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
