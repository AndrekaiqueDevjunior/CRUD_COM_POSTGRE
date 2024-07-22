import os
import logging
from flask import Flask, jsonify, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import psycopg2
from psycopg2 import OperationalError, Error
from dotenv import load_dotenv
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
# Carregar variáveis de ambiente do arquivo .env
load_dotenv()

# Criação da instância do Flask
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallbacksecretkey')  # Usar a chave secreta do .env ou um valor padrão

# Configurações do Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # Usar variável de ambiente
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # Usar variável de ambiente
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

# Configurações adicionais
app.config['SECURITY_PASSWORD_SALT'] = os.getenv('SECURITY_PASSWORD_SALT', 'my_precious_two')

UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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
        print(f"Error connecting to the database: {e}")
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = connect_to_postgres()
        if conn:
            cur = conn.cursor()
            cur.execute("SELECT password, profile_picture FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            cur.close()
            conn.close()
            if user and check_password_hash(user[0], password):
                session['username'] = username
                session['profile_picture'] = user[1]  # Save the profile picture URL in the session
                flash(f'Bem-vindo, {username}!', 'success')
                return redirect(url_for('menu'))
            else:
                flash("Usuário ou senha inválidos.")
                return render_template('login.html')
        else:
            flash("Erro ao conectar ao banco de dados.")
            return render_template('login.html')
    return render_template('login.html')

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


@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('profile_picture', None)  # Remove the profile picture from session
    flash('Você foi desconectado com sucesso.', 'info')
    return redirect(url_for('login'))

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


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']  # Adicione esta linha
        profile_picture = request.files.get('profile_picture')

        hashed_password = generate_password_hash(password)
        picture_filename = save_profile_picture(profile_picture)

        try:
            execute_query(
                "INSERT INTO users (username, password, email, profile_picture) VALUES (%s, %s, %s, %s)",
                (username, hashed_password, email, picture_filename)  # Adicione o email aqui
            )
            flash(f"Usuário {username} registrado com sucesso!")
            return redirect(url_for('login'))
        except Error as e:
            logging.error(f"Erro ao registrar usuário {username}: {e}")
            flash("Usuário já existe.")
            return render_template('register.html')
    return render_template('register.html')


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

@app.route('/view_user/<int:user_id>')
def view_user(user_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    conn = connect_to_postgres()
    if conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, profile_picture FROM users WHERE id = %s", (user_id,))
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
        password = request.form['password']
        
        file = request.files.get('profile_picture')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            profile_picture_url = url_for('uploaded_file', filename=filename)
        else:
            profile_picture_url = user['profile_picture']

        update_user(user_id, username, email, password, profile_picture_url)
        flash('Usuário atualizado com sucesso!', 'success')
        return redirect(url_for('users'))

    return render_template('edit_user.html', user=user)

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

@app.route('/search', methods=['GET'])
def search_users():
    query = request.args.get('query', '')
    if query:
        conn = connect_to_postgres()
        users = []
        if conn:
            cur = conn.cursor()
            cur.execute("SELECT id, username FROM users WHERE username ILIKE %s", (f'%{query}%',))
            users = cur.fetchall()
            cur.close()
            conn.close()
        return render_template('users.html', users=users)
    return redirect(url_for('users'))

def create_users_table():
    conn = connect_to_postgres()
    if conn:
        cur = conn.cursor()
        create_table_query = '''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            profile_picture VARCHAR(255)
        );
        '''
        try:
            cur.execute(create_table_query)
            conn.commit()
        except Exception as e:
            print(f"Error creating table: {e}")
        finally:
            cur.close()
            conn.close()



if __name__ == '__main__':
    app.run(debug=True)