import os
import math

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, usd, apologyc, apology1

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///cafeteria.db")

# Creating SQL Tables
db.execute("CREATE TABLE IF NOT EXISTS employee(id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, employeeid TEXT, hash TEXT NOT NULL, cash NUMERIC DEFAULT 1000.00)")
db.execute("CREATE TABLE IF NOT EXISTS chef(id1 INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,chefid TEXT,hashh TEXT)")
db.execute("INSERT INTO chef (chefid,hashh) VALUES (?,?)", "CHEF_BAKERY", generate_password_hash("BAKE12", method = 'pbkdf2:sha256', salt_length = 16))
db.execute("CREATE TABLE IF NOT EXISTS items(id2 INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,iid INTEGER,item TEXT,price TEXT,quantity TEXT)")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# As soon as website loads the user should select his role - Chef or Customer
@app.route("/", methods=["GET", "POST"])
def first():
    if request.method == "POST":
        if not(request.form.get("role")):
            return apology1("Select your role")
        # If the user is a customer ..customer login page is redirected
        if request.form.get("role") == "Customer":
            return redirect("/login")
        # If the user is a chef ..chef login page is redirected
        elif request.form.get("role") == "Chef":
            return redirect("/loginch")
    else:
        return render_template("first.html")


@app.route("/loginch", methods=["GET", "POST"])
def loginch():
    """Log user in"""


    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":


        # Ensure username was submitted
        if not request.form.get("chefid"):
            return apologyc("Enter the chef id", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apologyc("Enter the password", 403)

        d=db.execute("SELECT * FROM chef")
        if request.form.get("chefid")!= d[0]["chefid"] or not check_password_hash(d[0]["hashh"], request.form.get("password")) :
            return apologyc("Invalid Login")

        # Remember which user has logged in
        session["user_id"] = d[0]["id1"]

        # Redirect user to home page
        return redirect("/chefpage")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("loginch.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("employeeid"):
            return apology("must provide your employee id", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM employee WHERE employeeid = ?", request.form.get("employeeid"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid employee id and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/menu")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/create account", methods=["GET", "POST"])
def create_account():
    """Register user"""
    if request.method == "POST":
        employeeid = request.form.get("employeeid")
        passwordd = request.form.get("password")
        confirmation = request.form.get("confirmation")
        # Checking for the errors that may arise due to the inconsistent data provided by user
        if not employeeid:
            return apology("Enter your employee id")
        ids = db.execute("SELECT employeeid FROM employee")
        for id in ids:
            if id["employeeid"] == employeeid:
                return apology("Incorrect employee ID")
        if not passwordd:
            return apology("Enter password")
        if passwordd != confirmation:
            return apology("Password not matching with the confirmation")
        # Variable to store the hash of the password for security reasons
        hashh = generate_password_hash(passwordd, method='pbkdf2:sha256', salt_length=16)
        # Inserting the username and the hash of his password in the table
        db.execute("INSERT INTO employee (employeeid,hash) VALUES(?,?)", employeeid, hashh)
        rows = db.execute("SELECT * FROM employee WHERE employeeid = ?", employeeid)
        session["user_id"] = rows[0]["id"]
        return redirect("/menu")
    else:
        return render_template("create_account.html")


@app.route("/chefpage", methods=["GET", "POST"])
@login_required
def chefpage():
    """Get stock quote."""
    if request.method == "POST":
        i=request.form.get("item")
        p=request.form.get("price")
        q=str(request.form.get("quantity"))
        if not i:
            return apologyc("Empty item field.Enter item.")
        if not p:
            return apologyc("Empty price field.Enter price.")
        if not q:
            return apologyc("Empty quantity field.Enter quantity.")
        infos=db.execute("SELECT * FROM chef WHERE id1=?",session["user_id"])
        r=db.execute("SELECT * FROM items WHERE iid=? AND item=?",session["user_id"],i)
        if i and p and q:
            if r:
                if str(p)==r[0]["price"] :
                    db.execute("UPDATE items SET quantity=? WHERE iid=? AND item=?",str(int(q)+int(r[0]["quantity"])),session["user_id"],r[0]["item"])
                else:
                    return apologyc("You have inserted the same item with different prices")
            else:
                db.execute("INSERT INTO items (iid,item,price,quantity) VALUES(?,?,?,?)",session["user_id"],i,p,q)
        return redirect("/chefpage")
    else:
        x=db.execute("SELECT * FROM items WHERE iid=?",session["user_id"])
        return render_template("chefpage.html",info=x)


@app.route("/update", methods=["POST"])
def update():
        for key in request.form:
            if key.startswith('itm.'):
                id1_ = key.partition('.')[-1]
                value1 = request.form[key]

        for key in request.form:
            if key.startswith('prc.'):
                id2_ = key.partition('.')[-1]
                value2 = request.form[key]

        for key in request.form:
            if key.startswith('qty.'):
                id3_ = key.partition('.')[-1]
                value3 = request.form[key]
        itm=value1
        prc=value2
        qty=value3
        if id1_:
            idd=db.execute("SELECT * FROM items WHERE item=?",id1_)
        elif id2_:
            idd=db.execute("SELECT * FROM items WHERE item=?",id2_)
        else:
            idd=db.execute("SELECT * FROM items WHERE item=?",id3_)
        if itm:
            db.execute("UPDATE items SET item=? WHERE id2=?",itm,idd[0]["id2"])
        if prc:
            db.execute("UPDATE items SET price=? WHERE id2=?",prc,idd[0]["id2"])
        if qty:
            db.execute("UPDATE items SET quantity=? WHERE id2=?",qty,idd[0]["id2"])
        return redirect("/chefpage")


@app.route("/delete", methods=["POST"])
@login_required
def delete():
    for key in request.form:
            if key.startswith('del.'):
                id = key.partition('.')[-1]
    if id:
        idd=db.execute("SELECT * FROM items WHERE item=?",id)
    db.execute("DELETE FROM items WHERE item=?",idd[0]["item"])
    return redirect("/chefpage")


@app.route("/menu", methods=["GET"])
@login_required
def menu():
    if request.method == "GET":
        x=db.execute("SELECT * FROM items")
        u=db.execute("SELECT * FROM employee WHERE id=?",session["user_id"])
        return render_template("menu.html",info=x,user=u[0]["employeeid"])


@app.route("/placeorder",methods=["POST"])
@login_required
def placeorder():
    for key in request.form:
            if key.startswith('order.'):
                id1_ = key.partition('.')[-1]
                value1 = request.form[key]
    if id1_:
            idd=db.execute("SELECT * FROM items WHERE item=?",id1_)
    id=idd[0]["id2"]
    qty=value1
    if not qty:
        return apology("Enter the quantity of your order")
    db.execute("CREATE TABLE IF NOT EXISTS orders(id3 INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,uid INTEGER,item TEXT,price TEXT,quantity TEXT,qty TEXT,net TEXT)")
    rows=db.execute("SELECT * FROM items WHERE id2=?",id)
    n=float(rows[0]["price"])*float(qty)
    r=db.execute("SELECT * FROM employee WHERE id=?",session["user_id"])
    c=r[0]["cash"]
    re=c-n
    if int(re) < 0:
        return redirect("/wallet")
    else:
        db.execute("UPDATE employee SET cash=? WHERE id=?",re,session["user_id"])
        db.execute("UPDATE items SET quantity=? WHERE id2=?",str(int(rows[0]["quantity"])-int(qty)),id)
        rowss=db.execute("SELECT * FROM items WHERE id2=?",id)
        d=db.execute("SELECT * FROM orders WHERE uid=? AND item=?",session["user_id"],rows[0]["item"])
        if d:
            db.execute("UPDATE orders SET qty=? WHERE uid=? AND item=?",math.trunc(float(d[0]["qty"])+float(qty)),session["user_id"],rows[0]["item"])
            rows1=db.execute("SELECT * FROM items WHERE id2=?",id)
            qty1=db.execute("SELECT * FROM orders WHERE uid=? AND item=?",session["user_id"],rows[0]["item"])
            ne=float(rows1[0]["price"])*float(qty1[0]["qty"])
            ro=db.execute("SELECT * FROM employee WHERE id=?",session["user_id"])
            c1=ro[0]["cash"]
            re1=c1-ne
            db.execute("UPDATE orders SET net=? WHERE uid=? AND item=?",usd(ne),session["user_id"],rows[0]["item"])
        else:
            db.execute("INSERT INTO orders (uid,item,price,quantity,qty,net) VALUES (?,?,?,?,?,?)", session["user_id"], rows[0]["item"], usd(float(rows[0]["price"])), (rowss[0]["quantity"]).split('.')[0], str((qty.split('.')[0])),usd(n))
    return redirect("/menu")


@app.route("/order", methods=["GET"])
@login_required
def order():
    rows=db.execute("SELECT * FROM orders WHERE uid=?",session["user_id"])
    tot=0
    for r in rows:
        tot=tot+float(r["net"][1:].replace(',', ''))
    cash=db.execute("SELECT * FROM employee WHERE id=?",session["user_id"])
    u=db.execute("SELECT * FROM employee WHERE id=?",session["user_id"])
    return render_template("order.html",tot=usd(tot),cash=usd(float(cash[0]["cash"])),info=rows,uid=session["user_id"],user=u[0]["employeeid"])


@app.route("/updateorder", methods=["POST"])
@login_required
def updateorder():
    for key in request.form:
            if key.startswith('order.'):
                id1_ = key.partition('.')[-1]
                value1 = request.form[key]
    rows=db.execute("SELECT * FROM orders WHERE uid=? AND item=?",session["user_id"],id1_)
    qty=rows[0]["qty"]
    quantity=rows[0]["quantity"]
    sum=int(qty)+int(quantity)
    if int(value1)>sum:
        return apology("Quantity not available")
    if id1_:
        idd=db.execute("SELECT * FROM items WHERE item=?",id1_)
    q=value1
    net=db.execute("SELECT * FROM orders WHERE item=? AND uid=?",id1_,session["user_id"])
    q2=net[0]["qty"]
    if q:
        if int(q)<int(str(q2.partition('.')[0])):
            qt=-int(q)+int(str(q2.partition('.')[0]))
            net1=float(net[0]["net"][1:].replace(',', ''))
            n=float(qt)*float(idd[0]["price"])
            cash=db.execute("SELECT * FROM employee WHERE id=?",session["user_id"])
            re=(cash[0]["cash"])+n
            if int(re) < 0:
                return redirect("/wallet")
            else:
                db.execute("UPDATE employee SET cash=? WHERE id=?",re,session["user_id"])
            db.execute("UPDATE items SET quantity=? WHERE id2=?",str(math.trunc((float(idd[0]["quantity"])+float(-int(q)+int(str(q2.partition('.')[0])))))),idd[0]["id2"])
            db.execute("UPDATE orders SET qty=? WHERE uid=? AND item=?",str(q),session["user_id"],idd[0]["item"])
            db.execute("UPDATE orders SET net=? WHERE uid =? AND item=?",usd(-n+net1),session["user_id"],idd[0]["item"])
        elif int(q)>int(str(q2.partition('.')[0])):
            qt=int(q)-int(str(q2.partition('.')[0]))
            net1=float(net[0]["net"][1:].replace(',', ''))
            n=float(qt)*float(idd[0]["price"])
            cash=db.execute("SELECT * FROM employee WHERE id=?",session["user_id"])
            re=(cash[0]["cash"])-n
            if int(re) < 0:
                return redirect("/wallet")
            else:
                db.execute("UPDATE employee SET cash=? WHERE id=?",re,session["user_id"])
            db.execute("UPDATE items SET quantity=? WHERE id2=?",str(math.trunc((float(idd[0]["quantity"])-float(int(q)-int(str(q2.partition('.')[0])))))),idd[0]["id2"])
            db.execute("UPDATE orders SET qty=? WHERE uid=? AND item=?",str(q),session["user_id"],idd[0]["item"])
            db.execute("UPDATE orders SET net=? WHERE uid =? AND item=?",usd(n+net1),session["user_id"],idd[0]["item"])
    return redirect("/order")


@app.route("/deleteorder", methods=["POST"])
@login_required
def deleteorder():
    for key in request.form:
            if key.startswith('orderd.'):
                id1_ = key.partition('.')[-1]
    if id1_:
        idd=db.execute("SELECT * FROM items WHERE item=?",id1_)
    net=db.execute("SELECT * FROM orders WHERE item=? AND uid=?",id1_,session["user_id"])
    q2=net[0]["qty"]
    db.execute("UPDATE items SET quantity=? WHERE id2=?",str(math.trunc((float(idd[0]["quantity"])+float(int(str(q2.partition('.')[0])))))),idd[0]["id2"])
    de=db.execute("SELECT * FROM orders WHERE uid=? AND item=?",session["user_id"],idd[0]["item"])
    pr=de[0]["price"]
    qt=de[0]["qty"]
    r=db.execute("SELECT * FROM employee WHERE id=?",session["user_id"])
    re=r[0]["cash"]
    db.execute("UPDATE employee SET cash=? WHERE id=?",(float(re)+(float(pr[1:])*float(qt))),session["user_id"])
    db.execute("DELETE FROM orders WHERE uid=? AND item=?",session["user_id"],idd[0]["item"])
    return redirect("/order")


@app.route("/wallet", methods=["POST","GET"])
@login_required
def wallet():
    if request.method == "POST":
        acash=request.form.get("acash")
        if not acash:
            return apology("Enter the cash you would like to add to your wallet")
        c=db.execute("SELECT * FROM employee WHERE id=?",session["user_id"])
        db.execute("UPDATE employee SET cash=? WHERE id=?",(float(acash)+c[0]["cash"]),session["user_id"])
        u=db.execute("SELECT * FROM employee WHERE id=?",session["user_id"])
        return render_template("message.html",user=u[0]["employeeid"])
    else:
        c=db.execute("SELECT * FROM employee WHERE id=?",session["user_id"])
        u=db.execute("SELECT * FROM employee WHERE id=?",session["user_id"])
        return render_template("wallet.html",cash=c[0]["cash"],user=u[0]["employeeid"])


@app.route("/bill", methods=["POST"])
@login_required
def bill():
    for key in request.form:
            if key.startswith('bill.'):
                id1 = key.partition('.')[-1]
    if id1:
        b=db.execute("SELECT * FROM orders WHERE uid=?",id1)
        db.execute("CREATE TABLE IF NOT EXISTS bill(id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,uid INTEGER,name TEXT,item TEXT,price TEXT,qty TEXT,net TEXT)")
        for b1 in b:
            u=db.execute("SELECT * FROM employee WHERE id=?",session["user_id"])
            db.execute("INSERT INTO bill (uid,name,item,price,qty,net) VALUES (?,?,?,?,?,?)", session["user_id"], u[0]["employeeid"], b1["item"],b1["price"],b1["qty"],b1["net"])
    n=0
    for bi in b:
        n=n+float(bi["net"][1:].replace(',',''))
    u=db.execute("SELECT * FROM employee WHERE id=?",session["user_id"])
    return render_template("bill.html",bill=b,net=usd(n),user=u[0]["employeeid"])


@app.route("/cheforder", methods=["GET"])
@login_required
def cheforder():
    bill=db.execute("SELECT * FROM bill ORDER BY uid")
    l=[]
    bill2=db.execute("SELECT uid FROM bill ORDER BY uid ")
    for b in bill:
        if b["uid"] not in l:
            l.append(b["uid"])
    s=[]
    for i in l:
        s1=db.execute("SELECT * FROM bill  WHERE uid=? ORDER BY uid",i)
        s.append(s1)
    return render_template("orderc.html",bill=s)

