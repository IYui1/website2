from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request, has_request_context, g
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user,login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text , ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from typing import List
from hashlib import md5
import os


'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# TODO: Configure Flask-Login

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
db_path = os.path.join('D:\\ASUS\\.vscode\\frontend\\udemy2\\day-69-starting-files-blog-with-users\\instance', 'posts.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
db = SQLAlchemy(model_class=Base)
db.init_app(app)
author_id = db.Column(db.Integer, db.ForeignKey("users.id"))


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # Relationship with User
    user = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="post")

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(1000), nullable=False)

    # Relationship with BlogPost
    posts = relationship("BlogPost", back_populates="user")
    comments = relationship("Comment", back_populates="comment_author")
    
    
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"), nullable=False)  # Add this line
    
    comment_author = db.relationship("User", back_populates="comments")
    post = db.relationship("BlogPost", back_populates="comments")


    def is_active(self):
        return True



with app.app_context():
    db.create_all()
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

def only_commenter(function):
    @wraps(function)
    def check(*args, **kwargs):
        user = db.session.execute(db.select(Comment).where(Comment.author_id == current_user.id)).scalar()
        if not current_user.is_authenticated or current_user.id != user.author_id:
            return abort(403)
        return function(*args, **kwargs)
    return check

# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register',methods = ["POST","GET"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        )
        if user:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form,current_user=current_user)

# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods = ["POST","GET"])
def login():
    form_login = LoginForm()
    if form_login.validate_on_submit():
        email = form_login.email.data
        password = form_login.password.data
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('get_all_posts'))
        else:
            flash('Invalid email or password', 'error')
    return render_template("login.html", form=form_login,current_user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts,current_user=current_user)

# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form = CommentForm()
    gravatar_urls = {}  # Initialize an empty dictionary for the GET request
    
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        new_comment = Comment(
            post_id=post_id,
            author_id=current_user.id,
            text=comment_form.comment_text.data
        )
        db.session.add(new_comment)
        db.session.commit()
        
        # Update gravatar_urls after posting a comment
        
        flash('Your comment has been posted.')
        return redirect(url_for("get_all_posts", post_id=requested_post.id))
    
    # Only update gravatar_urls for GET request
    
    return render_template("post.html", post=requested_post,
                           logged_in=current_user.is_authenticated, form=comment_form)






# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,  # Gunakan nama user
            author_id=current_user.id,  # Gunakan ID user
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
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
        post.author = current_user.name  # Gunakan nama user
        post.author_id = current_user.id  # Gunakan ID user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route("/delete/comment/<int:comment_id>/<int:post_id>")
@only_commenter
def delete_comment(post_id, comment_id):
    post_to_delete = db.get_or_404(Comment, comment_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_id,current_user=current_user))

@app.route("/about")
def about():
    return render_template("about.html",current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html",current_user=current_user)


if __name__ == "__main__":
    app.run(debug=True, port=5002)
