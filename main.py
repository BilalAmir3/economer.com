from flask import Flask, render_template, redirect, url_for, flash , request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from flask_wtf import FlaskForm
from datetime import datetime, timedelta
from wtforms import StringField, SubmitField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length
from flask_login import current_user, LoginManager, logout_user, login_user, UserMixin, login_required
from flask_bcrypt import generate_password_hash, check_password_hash
from wtforms.widgets import TextArea

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///User.db'
app.config['SQLALCHEMY_BINDS'] = {
    'database2': 'sqlite:///Post.db',
}
app.config['SECRET_KEY'] = 'hello123456'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    passion = db.Column(db.String(120), nullable=False)
    about_author = db.Column(db.Text(50), nullable=True)
    password = db.Column(db.String(60), nullable=False)
    date_joined = db.Column(db.DateTime(datetime.utcnow()))

class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    passion = StringField('Passion', validators=[DataRequired()])
    about_author = TextAreaField('About Author(Optional)' , validators=[Length(max=60)])
    password = PasswordField('Password', validators=[DataRequired()])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    poster_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    poster = db.relationship('User', backref='posts')
    comments = db.relationship('Comment', backref='post')
    likes = db.relationship('Like', backref='post')

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = StringField('Content', validators=[DataRequired(), Length(min=2,max=3000)], widget=TextArea())

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text(1000), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='comments')

class CommentForm(FlaskForm):
   content = StringField('Content', validators=[DataRequired(), Length(min=2, max=3000)], widget=TextArea())

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    
with app.app_context():
    db.create_all()
    db.session.commit() 

@app.route('/dismiss' , methods=['GET' , 'POST'])
def dismiss():
    flash('')
    return redirect('/')

@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('dashboard.html' , title='Dashboard')
    else:
        form = RegistrationForm()
        return render_template('register.html' , form=form , title='Register')

@app.route('/register')
def register_page():
    form = RegistrationForm()
    return render_template('register.html' , form=form , title='Register')

@app.route('/dashboard')
@login_required
def dashboard():
    form = RegistrationForm()
    user_update = User.query.get_or_404(current_user.id)
    return render_template('dashboard.html', title='Dashboard', form=form , user_update=user_update)

@app.route('/dashboard/edit', methods=['GET', 'POST'])
@login_required
def edit_user():
    user_update = User.query.get_or_404(current_user.id)
    form = RegistrationForm(obj=user_update)

    if form.validate_on_submit():
        user_update.name = form.name.data
        user_update.username = form.username.data
        user_update.email = form.email.data
        user_update.passion = form.passion.data
        user_update.about_author = form.about_author.data

        try:
            db.session.commit()
            flash('User has been updated!')
            return redirect(url_for('dashboard'))
        except:
            flash('Whoops! Something went wrong while updating the user.')

    return render_template('edit_user.html', title='Edit User', form=form, user_update=user_update)

@app.route('/dashboard/delete', methods=['POST', 'GET'])
@login_required
def delete_user():
    user_to_delete = current_user 

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash('Account Deleted!')
        return redirect(url_for('register_account')) 
    except:
        flash('Whoops! Something went wrong!')
    
    return redirect(url_for('dashboard'))

@app.route('/user-add', methods=['GET', 'POST'])
def register_account():
    form = RegistrationForm()
    if form.validate_on_submit():
        user_username = User.query.filter_by(username=form.username.data).first()
        user_email = User.query.filter_by(email=form.email.data).first()
        if user_username:
            flash('Username Is Already In Use!')
        elif user_email:
            flash('Email Is Already In Use!')
        else:
            hashed_password = generate_password_hash(form.password.data).decode('utf-8')
            user = User(name=form.name.data, username=form.username.data, email=form.email.data,
                        passion=form.passion.data, password=hashed_password,date_joined=datetime.utcnow(),about_author=form.about_author.data)
            form.username.data = ''
            db.session.add(user)
            db.session.commit()
            flash(f'Your Account Been Created Now You can Login!')
            return render_template('login.html', form=form)
    return render_template('register.html', form=form, title='Register')


@app.route('/login' , endpoint='login')
def login_page():
    form = LoginForm()
    return render_template('login.html', form=form, title='Login')


@app.route('/login-user', methods=['GET', 'POST'])
def login_user_authenticate():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                flash('User Logged In Successfully!')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.')
        else:
            flash('Invalid username or password.')
    return render_template('login.html', form=form, title='Login')


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You Have Been Logged Out...')
    form = RegistrationForm()
    return render_template('register.html' , title='Register' , form=form)
 

@app.route('/add_post')
@login_required
def add_post_page():
    form = PostForm()
    return render_template('add_post.html', title='Add Post', form=form)


@app.route('/add_post_data', methods=['GET', 'POST'])
@login_required
def add_post():
    form = PostForm()
    if form.validate_on_submit():
        poster=current_user.id
        post = Post(
            title=form.title.data,
            poster_id=poster,
            content=form.content.data,
            date_posted=datetime.utcnow(),
        )
        db.session.add(post)
        db.session.commit()
        flash('Post posted!')
        return redirect(url_for('posts'))
    return render_template('add_post.html', title='Add Post', form=form,)


@app.route('/posts', methods=['GET', 'POST'])
def posts():
    posts = Post.query.order_by(desc(Post.date_posted)).all()
    return render_template('posts.html', title='Posts', posts=posts, id=current_user.id)

@app.route('/posts/<int:id>', methods=['POST', 'GET'])
@login_required
def view_post(id):
    post = Post.query.get_or_404(id)
    form = CommentForm()

    if form.validate_on_submit():
        comment = Comment(
            content=form.content.data,
            date_posted=datetime.utcnow(),
            post_id=post.id,
            user_id=current_user.id
        )
        db.session.add(comment)
        db.session.commit()
        flash('Comment added successfully!')

    return render_template('post.html', title='View Post', post=post, form=form)

@app.route('/posts/edit/<int:id>', methods=['POST', 'GET'])
@login_required
def edit_post(id):
    post = Post.query.get_or_404(id)
    form = PostForm()
    post_to_edit = Post.query.get_or_404(id)
    id = current_user.id
    if post_to_edit.poster_id == current_user.id or id == 1:
        if form.validate_on_submit():
            post.title = form.title.data
            post.content = form.content.data
            db.session.commit()

            flash('Post Has Been Updated!')
            form = CommentForm()
            return render_template('post.html', id=post.id, title='Post', post=post, form=form)
    else:
        flash('You can\'t update other user\'s posts!')
    form.title.data = post.title
    form.content.data = post.content
    return render_template('edit_post.html', title='Edit Post', form=form , id=current_user.id)

@app.route('/posts/delete/<int:id>', methods=['POST', 'GET'])
@login_required
def delete_post(id):
    post_to_delete = Post.query.get_or_404(id)
    id = current_user.id
    if post_to_delete.poster_id == current_user.id or id == 1:
        try:
            db.session.delete(post_to_delete)
            db.session.commit()
            flash('Post Deleted!')
        except:
            flash('Whoops! Something went wrong while deleting the post!')
    else:
        flash("You can't delete other user's post!")

    posts = Post.query.order_by(desc(Post.date_posted)).all()
    return render_template('posts.html', title='Posts', posts=posts, id=current_user.id)

@app.route('/comment/edit/<int:post_id>/<int:comment_id>', methods=['GET', 'POST'])
@login_required
def edit_comment(post_id, comment_id):
    comment = Comment.query.get_or_404(comment_id)
    form = CommentForm(obj=comment)

    if form.validate_on_submit():
        comment.content = form.content.data
        db.session.commit()
        flash('Comment has been updated!')
        return redirect(url_for('view_post', id=post_id))

    return render_template('edit_comment.html', title='Edit Comment', form=form, comment=comment)


@app.route('/comment/delete/<int:post_id>/<int:comment_id>', methods=['POST', 'GET'])
@login_required
def delete_comment(post_id, comment_id):
    comment = Comment.query.get_or_404(comment_id)

    db.session.delete(comment)
    db.session.commit()
    flash('Comment has been deleted!')
    return redirect(url_for('view_post', id=post_id))

if __name__ == "__main__":
    app.run(debug=False,host='0.0.0.0')
