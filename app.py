from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
from data import Articles
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://localhost:5432/users'
db = SQLAlchemy(app)
Articles = Articles()


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/articles")
def articles():
    return render_template("articles.html", articles=Articles)


@app.route("/article/<string:id>")
def article(id):
    return render_template("article.html", id=id)

#REGISTRATION FORM
class RegisterForm(Form):
    name = StringField("Name", [validators.Length(min=1, max=50)])
    email = StringField("Email", [validators.Length(min=6, max=50)])
    username = StringField("Username", [validators.Length(min=4, max=25)])
    password = PasswordField("Password", [validators.DataRequired(
    ), validators.EqualTo("confirm", message="Passwords do not match")])
    confirm = PasswordField("Confirm Password")

#REGISTER
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form)
    if request.method == "POST" and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        eng = create_engine('postgresql:///users')
        con = eng.connect()
        con.execute("INSERT INTO users(name,email,username,password) VALUES(%s,%s,%s,%s)",(name,email,username,password))
        con.close()

        flash("You are now registered and can log in","success")

        redirect(url_for("home"))
    return render_template("register.html", form=form)

#LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method=="POST": 
        username=request.form["username"]
        password_candidate=request.form["password"]

        eng = create_engine('postgresql:///users')
        con = eng.connect()
        result = con.execute("SELECT * FROM users WHERE username=%s",[username])

        if result.fetchone() or result.fetchone()[0]:
            data= result.fetchone()
            password=data["password"]

            if sha256_crypt.verify(password_candidate,password):
                session["logged_in"]=True
                session["username"]=username

                flash("You are now logged in","success")
                return redirect(url_for("dashboard"))
            else:
                error="PASSWORD NOT  MATCHED"
                return render_template("login.html",error=error)
                
                con.close()

        else:
            error="NO USER"
            return render_template("login.html",error=error)
        

    return render_template("login.html")

#CHECK IF USER LOGGED IN
def is_logged_in(f):
    @wraps(f)
    def wrap(*args,**kwargs):
        if "logged_in" in session:
            return f(*args,**kwargs)
        else:
            flash("Unauthorized please log in","danger")
            return redirect(url_for("login"))

#LOGOUT
@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    flash("You are now logged out","success")
    return redirect(url_for("login"))

#DASHBOARD
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    return render_template("dashboard.html")

if __name__ == '__main__':
    app.secret_key="12345"
    app.run(debug=True)
