from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
# from data import Articles
# from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://localhost:5432/users'
# db = SQLAlchemy(app)
# Articles = Articles()


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/articles")
def articles():
    eng = create_engine('postgresql:///users')
    con = eng.connect()
    result = con.execute("select * from articles")
    articles = result.fetchall()

    if result>0:
        return render_template("articles.html",articles=articles)
    else:
        msg = "No articles found"
        return render_template("articles.html",msg = msg)

    con.close()


@app.route("/article/<string:id>")
def article(id):

    eng = create_engine('postgresql:///users')
    con = eng.connect()
    result = con.execute("select * from articles where id=%s",[id])
    article = result.fetchone()

    return render_template("article.html", article=article)

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

        if result>0:
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

        else:
            error="NO USER"
            return render_template("login.html",error=error)
        
        con.close()

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
    return wrap

#LOGOUT
@app.route("/logout", methods=["GET", "POST"])
@is_logged_in 
def logout():
    session.clear()
    flash("You are now logged out","success")
    return redirect(url_for("login"))

#DASHBOARD
@app.route("/dashboard", methods=["GET", "POST"])
@is_logged_in
def dashboard():
    eng = create_engine('postgresql:///users')
    con = eng.connect()
    result = con.execute("select * from articles")
    articles = result.fetchall()

    if result>0:
        return render_template("dashboard.html",articles=articles)
    else:
        msg = "No articles found"
        return render_template("dashboard.html",msg = msg)

    con.close()

#ARTICLE FORM CLASS
class ArticleForm(Form):
    title = StringField("Title", [validators.Length(min=1, max=200)])
    body = TextAreaField("Body", [validators.Length(min=30)])

#ADD ARTICLE
@app.route("/add_article", methods=["GET", "POST"])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method  == "POST" and form.validate():
        title = form.title.data
        body = form.body.data

        eng = create_engine('postgresql:///users')
        con = eng.connect()
        con.execute("INSERT INTO articles(title,body,author) VALUES(%s,%s,%s)",(title,body,session["username"]))
        con.close()

        flash("Article created","success")

        return redirect(url_for("dashboard"))

    return render_template("add_article.html", form=form)

#EDIT ARTICLE
@app.route("/edit_article/<string:id>", methods=["GET", "POST"])
@is_logged_in
def edit_article(id):
    eng = create_engine('postgresql:///users')
    con = eng.connect()
    result = con.execute("select * from articles where id=%s",[id])
    article = result.fetchone()

    form = ArticleForm(request.form)

    form.title.data = article["title"]
    form.body.data = article["body"]

    if request.method  == "POST" and form.validate():
        title = request.form["title"]
        body = request.form["body"]

        eng = create_engine('postgresql:///users')
        con = eng.connect()
        con.execute("update articles set title=%s,body=%s where id=%s",(title,body,id))
        con.close()

        flash("Article updated","success")

        return redirect(url_for("dashboard"))

    return render_template("edit_article.html", form=form)

@app.route("/delete_article/<string:id>", methods=["POST"])
@is_logged_in
def delete_article(id):
    eng = create_engine('postgresql:///users')
    con = eng.connect()
    con.execute("delete from articles where id=%s",[id])
    con.close()

    flash("Article deleted", "success")

    return redirect(url_for("dashboard"))

if __name__ == '__main__':
    app.secret_key="12345"
    app.run(debug=True)
