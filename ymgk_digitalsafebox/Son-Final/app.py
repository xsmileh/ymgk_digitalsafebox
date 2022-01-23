import os
import datetime
from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask import flash
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import request, send_from_directory, jsonify,send_file
from cryptography.fernet import Fernet
import socket

from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad









APP_ROOT = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)

app.config["FILE_UPLOAD"]=APP_ROOT+"\\static\\uploadfile"

app.config["SAFEBOX"]=APP_ROOT+"\\safebox"



app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class FileContents(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(300))
    data=db.Column(db.String())
    edata=db.Column(db.String())
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





@app.route("/upload", methods=['GET', 'POST'])
def upload():

    
    if request.method == 'GET':
        pass
    else:


        userfilepass = request.form['userkey']


        for file in request.files.getlist("file"):
            file=request.files["file"]

        if file.filename == '':
            flash('Lütfen bir dosya yükleyiniz!')
            return render_template("dashboard.html")

        else:
            target=app.config["SAFEBOX"]
            uploadfile=app.config["FILE_UPLOAD"]



            key = Fernet.generate_key()
            f = Fernet(key)


            file.save(os.path.join(app.config["FILE_UPLOAD"],file.filename))

            
            with open(app.config["FILE_UPLOAD"]+"\\"+file.filename,"rb") as new_enc_file:
                original=new_enc_file.read()
                original2 = f.encrypt(original)
                original3=str(original2)


            encrypted=AESCipher(userfilepass).encrypt(original3).decode('utf-8')


            newFile=FileContents(name=file.filename, data=original, edata=encrypted, key=key, user=current_user.username, date=datetime.datetime.now())
            db.session.add(newFile)
            db.session.commit()


            myfiles=FileContents.query.all()

            for row in myfiles:
                dbid=row.id
                dbname=row.name
                dbdata=row.data
                dbedata=row.edata
                dbkey=row.key
                dbuser=row.user
                dbdate=row.date



            # UPLOAD EDİLEN DOSYANIN STATIC/UPLOADFILE İSİMLİ BİR KLASÖRE KAYDOLMASI İÇİN.
            # file.save(os.path.join(app.config["SAFEBOX"],str(dbid)+"-"+str(dbuser)+"-"+file.filename))
            # with open(app.config["SAFEBOX"]+"\\"+str(dbid)+"-"+str(dbuser)+"-"+file.filename,"wb") as new_enc_file:
                # new_enc_file.write(encrypted)
                # new_enc_file.close()


    flash('Dosyanız başarıyla şifrelenerek kaydedildi!')
    return render_template("dashboard.html")



@app.route("/download", methods=['GET', 'POST'])
def download():

    userfilepass2 = request.form['userkey2']
    fileid = request.form['fileid']
    fileid=int(fileid)
    
    if request.method == 'GET':
        pass
    else:

        myfiles=FileContents.query.filter_by(id=fileid)


        for rows in myfiles:
            if(fileid==rows.id):

                dbid=rows.id
                dbname=rows.name
                dbdata=rows.data
                dbedata=rows.edata
                dbkey=rows.key
                dbuser=rows.user
                dbdate=rows.date

                try:
                    decrypted=AESCipher(userfilepass2).decrypt(dbedata).decode("utf-8")
                    decrypted=decrypted[2:-1]
                    decrypted=decrypted.encode("utf-8")
                    f=Fernet(dbkey)
                    decrypted=f.decrypt(decrypted)


                    #path = APP_ROOT+"\\static\\uploadfile\\1.txt"


                    with open(app.config["FILE_UPLOAD"]+"\\"+"deneme","wb") as newdecfile:
                        newdecfile.write(decrypted)
                        newdecfile.close()
                        #newdecfile.save(app.config["FILE_UPLOAD"]+"\\"+"deneme"+"."+dbname.split(".")[1])


                    path=app.config["FILE_UPLOAD"]+"\\"+"deneme"
                    try:
                        flash(dbname+' isimli dosyanızın şifresi başarıyla çözülmüştür.')
                        return send_file(path, as_attachment=True)
                    except:
                        flash("Dosya gönderilemedi")




                    # try:
                    #     flash(dbname+' isimli dosyanızın şifresi başarıyla çözülmüştür.')
                    #     return send_file('./tmp/{}'.format(dbname), as_attachment=True)

                    # except:
                    #     return flash("Dosya indirilemedi")




                except:
                    flash("Şifre Hatalı")

            else:
                flash("Hata")



    #flash(filebilgi)
    return render_template("dashboard.html")





@app.route("/remove",methods=['GET'])
def remove():
    return render_template("dashboard.html")




@app.route('/dashboard', methods=["GET"])
@login_required
def dashboard():
    myfiles=FileContents.query.all()
    return render_template('dashboard.html', name=current_user.username, email=current_user.email, my_files=myfiles, id=current_user.id)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))



# @app.route("/get_my_ip", methods=["GET"])
# def get_my_ip():
#     return jsonify({request.environ.get('HTTP_X_REAL_IP', request.remote_addr)}), 200


@app.route("/get_ip", methods=["GET"])
def get_ip():
    data=socket.gethostbyname(socket.getfqdn())
    return render_template('dashboard.html', data=data)



class Encryptor():

    # KEY OLUŞTURMA ve KEY'İ KAYDETME
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

        return encrypted


    def file_decrypt(self, key, encrypted_file, decrypted_file):
        
        f = Fernet(key)

        with open(encrypted_file, 'rb') as file:
            encrypted = file.read()

        decrypted = f.decrypt(encrypted)

        with open(decrypted_file, 'wb') as file:
            file.write(decrypted)




class AESCipher:
    def __init__(self, key):
        self.key = md5(key.encode('utf8')).digest()

    def encrypt(self, data):
        iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data.encode('utf-8'), 
            AES.block_size)))

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)







if __name__ == '__main__':
    app.run(debug=True)







