from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask import flash
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from flask import request, send_from_directory
from cryptography.fernet import Fernet
import datetime




#js = 'function message() {alertify.alert("Hi"); }'
#py=js2py.eval_js(js)






APP_ROOT = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\ES\\Desktop\\database.db'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///D:\\ymgk_digitalsafebox\\hafta_7-1\\digitalsafebox_project\\database.db'


bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class FileContents(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(300))
    data=db.Column(db.LargeBinary)
    # e_data=db.Column(db.LargeBinary)
    key=db.Column(db.String(1000))
    user=db.Column(db.String(100))
    date=db.Column(db.String(100))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Şifre', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Beni hatırla')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Hatalı Email'), Length(max=50)])
    username = StringField('Kullanıcı Adı', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Şifre', validators=[InputRequired(), Length(min=8, max=80)])


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

        
        flash('Hatalı Kullanıcı Adı veya Şifre')
        return  redirect(url_for('login'))

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

        flash('Kullanıcı başarıyla kaydedildi')
        return render_template('signup.html', form=form)
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)



@app.before_first_request
def create_tables():
    db.create_all()


@app.route("/upload", methods=["POST"])
def upload():


    target = os.path.join(APP_ROOT, 'safebox/')

    if not os.path.isdir(target):
        os.mkdir(target)


    for upload in request.files.getlist("file"):
        filename = upload.filename

      


        # HERHANGİ DOSYA UZANTISI İÇİN
        # # This is to verify files are supported
        # ext = os.path.splitext(filename)[1]
        # if (ext == ".jpg") or (ext == ".png"):
        #     print("File supported moving on...")
        # else:
        #     render_template("Error.html", message="Files uploaded are not supported...")



        # destination = "/".join([target, filename])




        encryptor=Encryptor()
        # mykey=encryptor.key_create()
        key = Fernet.generate_key()




        #OLUŞTURULAN KEY'i DİZİNE KAYDETMEK İÇİN
        # encryptor.key_write(mykey, str(os.path.splitext(filename)[0])+'.key')
        # loaded_key=encryptor.key_load(str(os.path.splitext(filename)[0])+'.key')



        #DOSYA ŞİFRELEME/DİZİN:safebox
        encryptor.file_encrypt(key,"C:\\Users\\ES\\Desktop\\"+filename, target+"e-"+filename)

        #ŞİFRELİ DOSYAYI ÇÖZME/DİZİN:safebox
        encryptor.file_decrypt(key, target+"e-"+filename, target+"d-"+filename)
        efile=open("./safebox/e-"+filename,"rb")


        # print("Accept incoming file:", filename)
        # print("Save it to:", destination)
        # # upload.save(destination)

    # return send_from_directory("safebox", filename, as_attachment=True)

        file=request.files["file"]
        newFile=FileContents(name=file.filename, data=efile.read(), key=key, user=current_user.username, date=datetime.datetime.now())
        db.session.add(newFile) 
        db.session.commit()

    flash('Dosyanız başarıyla şifrelenerek kaydedildi!')
    return render_template("dashboard.html", image_name=filename)


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

    return render_template('dashboard.html', name=current_user.username, email=current_user.email)



@app.route('/logout')
@login_required

def logout():
    logout_user()
    return redirect(url_for('index'))




class Encryptor():


    #KEY OLUŞTURMA ve KEY'İ KAYDETME
    # def key_create(self):
    #     key = Fernet.generate_key()
    #     return key

    # def key_write(self, key, key_name):
    #     with open(key_name, 'wb') as mykey:
    #         mykey.write(key)

    # def key_load(self, key_name):
    #     with open(key_name, 'rb') as mykey:
    #         key = mykey.read()
    #     return key


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







