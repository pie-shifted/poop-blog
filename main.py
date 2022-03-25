from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap  # for quickly rendering WTF-Forms
from flask_ckeditor import CKEditor  # For writing blogs
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash  # for generating and checking hashes
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user, \
    logout_user  # Handling user account sessions and stuff.
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm  # imported WTForms
from flask_gravatar import Gravatar
from functools import wraps  # for decorators. lets the wrapper function inherit for original function

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Gravatar
gravatar = Gravatar(app)


# CONFIGURE TABLES
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(256), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)

    # One-To-Many relationships.
    # 'backref' is used by the child object to refer
    # to the User object and access its attributes.
    # e.g 'post.author.name'
    posts = db.relationship('BlogPost', backref="author")
    comments = db.relationship('Comment', backref="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # child relationship with user table
    # this Foreign Key refers to the primary key of the User.
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # One-To-Many relationship with comment table
    comments = db.relationship('Comment', backref="blog")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    # Many-To-One relationship with User and BlogPost Table
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))

    comment = db.Column(db.String(250), nullable=False)


# db.create_all()

# LOGIN STUFF
login_manager = LoginManager()
login_manager.init_app(app)


# this lets the login manager associate the user object (user record in the DB)
# with the current user. (or something like that)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# admin only decorator
def admin_only(f):
    """Calls the function only if it being accessed by the admin.
    In more literal terms, only calls and returns the decorated
    function if the current user's ID is 1. Otherwise,
    returns an error."""

    # 'wraps' decorator lets the wrapper function inherit the
    # original functions properties and whatnot.
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.id == 1:
            return f(*args, **kwargs)
        else:
            return abort(403)

    return wrapper


# VIEW FUNCTIONS

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()

    # checks if all form entries are valid
    if form.validate_on_submit():
        # checks if user already exists
        if User.query.filter_by(email=form.email.data).first():
            flash("User already exists. Try logging in instead.")
            return redirect(url_for('login'))

        # otherwise, adds user to DB
        hashed_pwd = generate_password_hash(form.password.data, salt_length=8)
        new_user = User(email=form.email.data, password=hashed_pwd, name=form.name.data)
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()

    # checks if all form entries are valid
    if form.validate_on_submit():
        # checks if user exists
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            # then checks if the given password matches with the existing user
            if check_password_hash(user.password, form.password.data):
                # if so, logs them in
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Password is incorrect.")
                return redirect(url_for('login'))
        else:
            flash("User does not exist.")
            return redirect(url_for('login'))

    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()

    # summits comments
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                user_id=current_user.id,
                post_id=requested_post.id,
                comment=comment_form.comment.data
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))

        else:
            flash("You need to be logged in to comment.")
            return redirect(url_for('login'))

    return render_template("post.html", post=requested_post, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y"),
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    # get the requested post from the URL
    post = BlogPost.query.get(post_id)

    # pre-populated form
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )

    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
