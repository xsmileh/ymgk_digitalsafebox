from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from flask import request, send_from_directory


from cryptography.fernet import Fernet




APP_ROOT = os.path.dirname(os.path.abspath(__file__))


app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\ES\\Desktop\\database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)












@app.route("/upload", methods=["POST"])
def upload():
    '''
    # this is to verify that folder to upload to exists.
    if os.path.isdir(os.path.join(APP_ROOT, 'files/{}'.format(folder_name))):
        print("folder exist")
    '''
    target = os.path.join(APP_ROOT, 'safebox/')

    print(target)
    if not os.path.isdir(target):
        os.mkdir(target)


    print(request.files.getlist("file"))
    for upload in request.files.getlist("file"):
        print(upload)
        print("{} is the file name".format(upload.filename))

        filename = upload.filename
        # cvp=str(filename_path[0]+filename_path[1])



      


        # HERHANGİ DOSYA UZANTISI İÇİN
        # # This is to verify files are supported
        # ext = os.path.splitext(filename)[1]
        # if (ext == ".jpg") or (ext == ".png"):
        #     print("File supported moving on...")
        # else:
        #     render_template("Error.html", message="Files uploaded are not supported...")



        destination = "/".join([target, filename])



        encryptor=Encryptor()
        mykey=encryptor.key_create()
        encryptor.key_write(mykey, 'mykey.key')
        loaded_key=encryptor.key_load('mykey.key')


        encryptor.file_encrypt(loaded_key,"C:\\Users\\ES\\Desktop\\"+filename, target+filename)
        # encryptor.file_decrypt(loaded_key, 'C:\\Users\\ES\\Desktop\\enc_1111.jpg', 'C:\\Users\\ES\\Desktop\\dec_1111.jpg')


        print("Accept incoming file:", filename)
        print("Save it to:", destination)

        # upload.save(destination)

    # return send_from_directory("safebox", filename, as_attachment=True)
    return render_template("complete.html", image_name=filename)


@app.route('/upload/<filename>')
def send_image(filename):
    return send_from_directory("safebox", filename)


# @app.route('/gallery')
# def get_gallery():
#     image_names = os.listdir('./safebox')
#     print(image_names)
#     return render_template("gallery.html", image_names=image_names)















@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))









class Encryptor():

    def key_create(self):
        key = Fernet.generate_key()
        return key

    def key_write(self, key, key_name):
        with open(key_name, 'wb') as mykey:
            mykey.write(key)

    def key_load(self, key_name):
        with open(key_name, 'rb') as mykey:
            key = mykey.read()
        return key


    def file_encrypt(self, key, original_file, encrypted_file):
        
        f = Fernet(key)

        with open(original_file, 'rb') as file:
            original = file.read()

        encrypted = f.encrypt(original)

        with open (encrypted_file, 'wb') as file:
            file.write(encrypted)

    def file_decrypt(self, key, encrypted_file, decrypted_file):
        
        f = Fernet(key)

        with open(encrypted_file, 'rb') as file:
            encrypted = file.read()

        decrypted = f.decrypt(encrypted)

        with open(decrypted_file, 'wb') as file:
            file.write(decrypted)














if __name__ == '__main__':
    app.run(debug=True)














