import os
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import psycopg2
from psycopg2 import OperationalError, Error
from dotenv import load_dotenv
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import dropbox
import requests

# Configuração do logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Carregar variáveis de ambiente do arquivo .env
load_dotenv()

# Criação da instância do Flask
app = Flask(__name__)

# Configurações do Flask
app.secret_key = os.getenv('SECRET_KEY', 'fallbacksecretkey')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB
app.config['UPLOAD_FOLDER'] = 'static/uploads/'
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}

# Configurações do Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

# Configurações adicionais
app.config['SECURITY_PASSWORD_SALT'] = os.getenv('SECURITY_PASSWORD_SALT', 'my_precious_two')

# Configuração do Dropbox
DROPBOX_CLIENT_ID = os.getenv('DROPBOX_CLIENT_ID')
DROPBOX_CLIENT_SECRET = os.getenv('DROPBOX_CLIENT_SECRET')
DROPBOX_REDIRECT_URI = os.getenv('DROPBOX_REDIRECT_URI')
DROPBOX_ACCESS_TOKEN = os.getenv('DROPBOX_ACCESS_TOKEN')
dbx = dropbox.Dropbox(DROPBOX_ACCESS_TOKEN)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def connect_to_postgres():
    try:
        conn = psycopg2.connect(
            dbname=os.getenv('DB_NAME'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            host=os.getenv('DB_HOST')
        )
        return conn
    except OperationalError as e:
        logging.error(f"Error connecting to the database: {e}")
        return None

def execute_query(query, params=None):
    conn = connect_to_postgres()
    if conn:
        cur = conn.cursor()
        cur.execute(query, params)
        conn.commit()
        cur.close()
        conn.close()

def save_profile_picture(profile_picture):
    if profile_picture and allowed_file(profile_picture.filename):
        picture_filename = secure_filename(profile_picture.filename)
        picture_path = os.path.join(app.config['UPLOAD_FOLDER'], picture_filename)
        profile_picture.save(picture_path)
        return picture_filename
    return None

def save_to_dropbox(local_path, dropbox_path):
    with open(local_path, 'rb') as f:
        dbx.files_upload(f.read(), dropbox_path)

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def is_logged_in():
    return 'username' in session

@app.route('/')
def index():
    if is_logged_in():
        return redirect(url_for('menu'))
    return render_template('index.html')

@app.route('/connect', methods=['GET'])
def connect():
    conn = connect_to_postgres()
    if conn:
        return redirect(url_for('login'))
    else:
        return render_template('index.html', error="Erro ao conectar ao banco de dados.")

@app.route('/menu')
def menu():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('menu.html')

@app.route('/users')
def users():
    if not is_logged_in():
        return redirect(url_for('login'))
    conn = connect_to_postgres()
    if conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username FROM users")
        users = cur.fetchall()
        cur.close()
        conn.close()
    else:
        users = []
    return render_template('users.html', users=users)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        profile_picture = request.files.get('profile_picture')
        
        if not username or not email or not password:
            flash('Todos os campos são obrigatórios.', 'danger')
            return render_template('register.html')

        hashed_password = generate_password_hash(password)
        picture_filename = None

        if profile_picture and allowed_file(profile_picture.filename):
            picture_filename = save_profile_picture(profile_picture)
            dropbox_path = f"/profile_pictures/{picture_filename}"
            save_to_dropbox(os.path.join(app.config['UPLOAD_FOLDER'], picture_filename), dropbox_path)

        try:
            conn = connect_to_postgres()
            if conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO users (username, email, password, profile_picture)
                    VALUES (%s, %s, %s, %s)
                """, (username, email, hashed_password, picture_filename))
                conn.commit()
                cur.close()
                conn.close()
                flash("Usuário cadastrado com sucesso!", 'success')
                return redirect(url_for('login'))
            else:
                flash("Erro ao conectar ao banco de dados.", 'danger')
        except Error as e:
            flash(f"Erro ao cadastrar usuário: {e}", 'danger')
    return render_template('register.html')

@app.route('/view_user/<int:user_id>')
def view_user(user_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    conn = connect_to_postgres()
    if conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, email, profile_picture FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        cur.close()
        conn.close()
    else:
        user = None
    return render_template('view_user.html', user=user)

def get_user_by_id(user_id):
    conn = connect_to_postgres()
    if conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, email, profile_picture FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if user:
            return {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'profile_picture': user[3]
            }
    return None

def update_user(user_id, username, email, password=None, profile_picture_url=None):
    conn = connect_to_postgres()
    if conn:
        cur = conn.cursor()
        if password:
            hashed_password = generate_password_hash(password)
            cur.execute("""
                UPDATE users
                SET username = %s, email = %s, password = %s, profile_picture = %s
                WHERE id = %s
            """, (username, email, hashed_password, profile_picture_url, user_id))
        else:
            cur.execute("""
                UPDATE users
                SET username = %s, email = %s, profile_picture = %s
                WHERE id = %s
            """, (username, email, profile_picture_url, user_id))
        conn.commit()
        cur.close()
        conn.close()

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    user = get_user_by_id(user_id)

    if not user:
        flash('Usuário não encontrado.', 'danger')
        return redirect(url_for('users'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form.get('password')
        
        file = request.files.get('profile_picture')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            dropbox_path = f"/profile_pictures/{filename}"
            save_to_dropbox(os.path.join(app.config['UPLOAD_FOLDER'], filename), dropbox_path)
            profile_picture_url = dropbox_path
        else:
            profile_picture_url = user['profile_picture']

        update_user(user_id, username, email, password, profile_picture_url)
        flash('Usuário atualizado com sucesso!', 'success')
        return redirect(url_for('users'))

    return render_template('edit_user.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = connect_to_postgres()
        if conn:
            cur = conn.cursor()
            cur.execute("SELECT id, username, password FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
            cur.close()
            conn.close()
            if user and check_password_hash(user[2], password):
                session['username'] = user[1]
                session['user_id'] = user[0]
                flash("Login bem-sucedido!", 'success')
                return redirect(url_for('menu'))
            else:
                flash("Credenciais inválidas. Tente novamente.", 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Você saiu com sucesso!', 'success')
    return redirect(url_for('login'))

@app.route('/dropbox_login')
def dropbox_login():
    auth_url = f"https://www.dropbox.com/oauth2/authorize?client_id={DROPBOX_CLIENT_ID}&response_type=code&redirect_uri={DROPBOX_REDIRECT_URI}"
    return redirect(auth_url)

@app.route('/dropbox_callback')
def dropbox_callback():
    code = request.args.get('code')
    if not code:
        flash('Código de autenticação não encontrado.', 'danger')
        return redirect(url_for('index'))

    token_url = 'https://api.dropboxapi.com/oauth2/token'
    payload = {
        'code': code,
        'grant_type': 'authorization_code',
        'client_id': DROPBOX_CLIENT_ID,
        'client_secret': DROPBOX_CLIENT_SECRET,
        'redirect_uri': DROPBOX_REDIRECT_URI
    }
    response = requests.post(token_url, data=payload)
    if response.status_code == 200:
        data = response.json()
        session['dropbox_access_token'] = data.get('access_token')
        flash('Conectado ao Dropbox com sucesso!', 'success')
        return redirect(url_for('index'))
    else:
        flash('Erro ao conectar ao Dropbox.', 'danger')
        return redirect(url_for('index'))

def refresh_dropbox_token(refresh_token):
    url = "https://api.dropboxapi.com/oauth2/token"
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': os.getenv('DROPBOX_CLIENT_ID'),
        'client_secret': os.getenv('DROPBOX_CLIENT_SECRET')
    }
    response = requests.post(url, data=data)
    if response.status_code == 200:
        new_token = response.json().get('access_token')
        # Atualize o token no seu arquivo .env ou outro local seguro
        # Aqui você deve garantir que o novo token seja armazenado corretamente
        return new_token
    else:
        # Trate erros de renovação de token
        print("Erro ao renovar o token:", response.json())
        return None


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        conn = connect_to_postgres()
        if conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
            cur.close()
            conn.close()
            if user:
                token = generate_confirmation_token(email)
                reset_url = url_for('reset_password', token=token, _external=True)
                msg = Message('Redefinição de Senha', sender=app.config['MAIL_USERNAME'], recipients=[email])
                msg.body = f'Para redefinir sua senha, clique no seguinte link: {reset_url}'
                try:
                    mail.send(msg)
                    flash('Um e-mail de redefinição de senha foi enviado.', 'info')
                except Exception as e:
                    flash(f'Houve um erro ao enviar o e-mail de redefinição de senha: {str(e)}', 'danger')
                return redirect(url_for('login'))
            else:
                flash('E-mail não encontrado.', 'danger')
    return render_template('reset_password_request.html')




@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        password = request.form['password']
        email = request.form['email']
        hashed_password = generate_password_hash(password)
        conn = connect_to_postgres()
        if conn:
            cur = conn.cursor()
            cur.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
            conn.commit()
            cur.close()
            conn.close()
            flash('Sua senha foi redefinida com sucesso.', 'success')
            return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

# Exemplo de uso
refresh_token = os.getenv('DROPBOX_REFRESH_TOKEN')
new_access_token = refresh_dropbox_token(refresh_token)
if new_access_token:
    # Atualize o Dropbox SDK com o novo token
    dbx = dropbox.Dropbox(new_access_token)

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if not is_logged_in():
        return redirect(url_for('login'))
    if request.method == 'POST':
        # Adicionar lógica para processar configurações
        flash('Configurações salvas com sucesso!', 'success')
        return redirect(url_for('settings'))
    return render_template('settings.html')


@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        feedback = request.form['feedback']
        
        # Cria a mensagem de e-mail
        msg = Message(
            'Novo Feedback Recebido',
            sender=email,  # E-mail remetente do usuário
            recipients=['andrekaidellisola@gmail.com'],  # E-mail destinatário
            body=f'Nome: {name}\nEmail: {email}\n\nFeedback:\n{feedback}'
        )

        # Adicione uma impressão para depuração
        print(f"Sending email to: {msg.recipients}")
        print(f"Email body: {msg.body}")

        # Envia o e-mail
        try:
            mail.send(msg)
            flash('Feedback enviado com sucesso!', 'success')
        except Exception as e:
            flash(f'Houve um erro ao enviar o feedback: {str(e)}', 'danger')
        
        return redirect(url_for('feedback'))
    
    return render_template('feedback.html')

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    conn = connect_to_postgres()
    if conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        cur.close()
        conn.close()
    flash("Usuário deletado com sucesso!")
    return redirect(url_for('users'))

if __name__ == '__main__':
    app.run(debug=True)
