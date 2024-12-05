from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from itsdangerous import URLSafeTimedSerializer
import smtplib
from email.mime.text import MIMEText
import traceback
from datetime import datetime, timedelta
from passlib.hash import argon2
import re
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui'
app.config['SECURITY_PASSWORD_SALT'] = 'sua_salt_secreta_aqui'
app.config['MAX_LOGIN_ATTEMPTS'] = 5
app.config['LOGIN_TIMEOUT'] = 5  # em minutos

# Configurações de e-mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'testeredesdistribuidas@gmail.com'
app.config['MAIL_PASSWORD'] = 'bsqh jccy mcrm rnxx'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Simulação de um banco de dados de usuários
users = {
    'mo': {
        'password': argon2.hash('mo123'),
        'role': 'super_admin',
        'email': 'moniquedemoraes@hotmail.com',
        'full_name': 'Monique Moraes'
    },
    'admin': {'password': argon2.hash('admin123'), 'role': 'admin', 'email': 'admin@example.com', 'full_name': 'Admin User'},
    'usuario': {'password': argon2.hash('user123'), 'role': 'cliente', 'email': 'user@example.com', 'full_name': 'Regular User'}
}

@app.context_processor
def inject_users():
    return dict(users=users)

class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(username):
    if username not in users:
        return None
    user = User()
    user.id = username
    return user

def hash_password(password):
    return argon2.hash(password)

def check_password(hashed_password, user_password):
    return argon2.verify(user_password, hashed_password)

def validate_password(password):
    """
    Valida a senha de acordo com as seguintes regras:
    - Pelo menos 8 caracteres
    - Pelo menos uma letra maiúscula
    - Pelo menos uma letra minúscula
    - Pelo menos um número
    - Pelo menos um caractere especial
    """
    if len(password) < 8:
        return False, "A senha deve ter pelo menos 8 caracteres."
    
    if not re.search(r"[A-Z]", password):
        return False, "A senha deve conter pelo menos uma letra maiúscula."
    
    if not re.search(r"[a-z]", password):
        return False, "A senha deve conter pelo menos uma letra minúscula."
    
    if not re.search(r"\d", password):
        return False, "A senha deve conter pelo menos um número."
    
    if not re.search(r"[ !@#$%&'()*+,-./[\\$$^_`{|}~"+r'"]', password):
        return False, "A senha deve conter pelo menos um caractere especial."
    
    return True, "Senha válida."

def send_email(to, subject, template):
    msg = MIMEText(template)
    msg['Subject'] = subject
    msg['From'] = app.config['MAIL_USERNAME']
    msg['To'] = to

    try:
        smtp_server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        smtp_server.ehlo()
        smtp_server.starttls()
        smtp_server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        smtp_server.send_message(msg)
        smtp_server.close()
        print(f"E-mail enviado com sucesso para: {to}")
        return True
    except Exception as e:
        print(f"Erro detalhado ao enviar e-mail:")
        print(traceback.format_exc())
        return False

def generate_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def verify_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
        return email
    except:
        return False

@app.route('/')
def home():
    return render_template('home.html')

login_attempts = {}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Verifica se o usuário existe
        if username not in users:
            flash('Usuário não encontrado.', 'error')
            return render_template('login.html')
        
        # Verifica se o usuário está bloqueado
        if username in login_attempts:
            attempts, last_attempt = login_attempts[username]
            if attempts >= app.config['MAX_LOGIN_ATTEMPTS']:
                if datetime.now() - last_attempt < timedelta(minutes=app.config['LOGIN_TIMEOUT']):
                    remaining_time = timedelta(minutes=app.config['LOGIN_TIMEOUT']) - (datetime.now() - last_attempt)
                    flash(f'Conta bloqueada. Tente novamente em {remaining_time.seconds // 60} minutos e {remaining_time.seconds % 60} segundos.', 'error')
                    return render_template('login.html', is_blocked=True)
                else:
                    # Reset das tentativas após o tempo de bloqueio
                    login_attempts.pop(username)
        
        # Verifica a senha usando argon2
        if argon2.verify(password, users[username]['password']):
            user = User()
            user.id = username
            login_user(user)
            flash('Login bem-sucedido!', 'success')
            login_attempts.pop(username, None)  # Remove as tentativas após login bem-sucedido
            if users[username]['role'] == 'super_admin':
                return redirect(url_for('admin'))
            return redirect(url_for('dashboard'))
        else:
            # Incrementa as tentativas de login
            if username not in login_attempts:
                login_attempts[username] = [1, datetime.now()]
            else:
                attempts, _ = login_attempts[username]
                login_attempts[username] = [attempts + 1, datetime.now()]
            
            remaining_attempts = app.config['MAX_LOGIN_ATTEMPTS'] - login_attempts[username][0]
            if remaining_attempts > 0:
                flash(f'Senha incorreta. Você tem mais {remaining_attempts} tentativa(s).', 'error')
            else:
                flash(f'Limite de tentativas atingido. Tente novamente em {app.config["LOGIN_TIMEOUT"]} minutos.', 'error')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

from passlib.hash import argon2
from flask import Flask, render_template, redirect, url_for, request, flash

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        full_name = request.form['full_name']
        email = request.form['email']

        if username in users:
            flash('Nome de usuário já existe. Por favor, escolha outro.', 'error')
        elif password != confirm_password:
            flash('As senhas não coincidem.', 'error')
        else:
            is_valid, message = validate_password(password)
            if not is_valid:
                flash(message, 'error')
            else:
                hashed_password = argon2.hash(password)
                users[username] = {
                    'password': hashed_password,
                    'full_name': full_name,
                    'email': email,
                    'role': 'pql'
                }
                flash('Conta criada com sucesso! Você pode fazer login agora.', 'success')
                return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/admin')
@login_required
def admin():
    if current_user.id not in users or users[current_user.id]['role'] not in ['admin', 'super_admin']:
        flash('Acesso negado. Você não tem privilégios de administrador.', 'error')
        return redirect(url_for('dashboard'))
    
    admin_filter = request.args.get('admin_filter', '').lower()
    user_filter = request.args.get('user_filter', '').lower()
    
    filtered_users = {
        username: user_data for username, user_data in users.items() 
        if (user_data['role'] in ['admin', 'super_admin'] and (not admin_filter or admin_filter in username.lower())) or
           (user_data['role'] in ['cliente', 'pql'] and (not user_filter or user_filter in username.lower()))
    }
    
    return render_template('admin.html', users=filtered_users)

@app.route('/admin/add_user', methods=['POST'])
@login_required
def add_user():
    if current_user.id not in users or users[current_user.id]['role'] not in ['admin', 'super_admin']:
        flash('Acesso negado. Você não tem privilégios de administrador.', 'error')
        return redirect(url_for('dashboard'))
    
    username = request.form['username']
    password = request.form['password']
    full_name = request.form['full_name']
    email = request.form['email']
    role = request.form['role']

    if username in users:
        flash('Nome de usuário já existe. Por favor, escolha outro.', 'error')
    elif role not in ['cliente', 'pql', 'admin']:
        flash('Tipo de usuário inválido.', 'error')
    else:
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'error')
        else:
            hashed_password = hash_password(password)
            users[username] = {
                'password': hashed_password,
                'full_name': full_name,
                'email': email,
                'role': role
            }
            flash('Novo usuário adicionado com sucesso!', 'success')
    
    return redirect(url_for('admin'))

@app.route('/admin/update_user/<username>', methods=['POST'])
@login_required
def update_user(username):
    if current_user.id not in users or users[current_user.id]['role'] not in ['admin', 'super_admin']:
        flash('Acesso negado. Você não tem privilégios de administrador.', 'error')
        return redirect(url_for('dashboard'))
    
    if username not in users:
        flash(f'Usuário {username} não encontrado.', 'error')
        return redirect(url_for('admin'))

    new_role = request.form.get('role')
    if new_role not in ['cliente', 'pql']:
        flash('Tipo de usuário inválido.', 'error')
        return redirect(url_for('admin'))

    if username == 'mo':
        flash('Não é permitido alterar o tipo do super admin.', 'error')
    elif users[username]['role'] == 'admin':
        flash('Não é permitido alterar o tipo de um administrador.', 'error')
    else:
        users[username]['role'] = new_role
        flash(f'Tipo de usuário de {username} alterado para {new_role} com sucesso.', 'success')
    
    return redirect(url_for('admin'))

@app.route('/admin/delete_user/<username>', methods=['POST'])
@login_required
def delete_user(username):
    if current_user.id not in users or users[current_user.id]['role'] not in ['admin', 'super_admin']:
        flash('Acesso negado. Você não tem privilégios de administrador.', 'error')
        return redirect(url_for('dashboard'))
    
    if username == 'mo':
        flash('Não é permitido excluir o super admin.', 'error')
    elif username == current_user.id:
        flash('Você não pode excluir seu próprio usuário.', 'error')
    elif username in users:
        del users[username]
        flash(f'Usuário {username} foi excluído com sucesso.', 'success')
    else:
        flash(f'Usuário {username} não encontrado.', 'error')
    
    return redirect(url_for('admin'))

@app.route('/profile')
@login_required
def profile():
    user_data = users.get(current_user.id, {})
    return render_template('profile.html', user=user_data)

from passlib.hash import argon2
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user, login_user

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        new_username = request.form['username']
        new_full_name = request.form['full_name']
        new_email = request.form['email']
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not check_password(users[current_user.id]['password'], current_password):
            flash('Senha atual incorreta.', 'error')
            return redirect(url_for('profile'))

        if new_username != current_user.id and new_username in users:
            flash('Nome de usuário já existe. Por favor, escolha outro.', 'error')
            return redirect(url_for('profile'))

        old_username = current_user.id
        users[new_username] = users.pop(old_username)
        users[new_username]['full_name'] = new_full_name
        users[new_username]['email'] = new_email

        if new_password:
            if new_password == confirm_password:
                is_valid, message = validate_password(new_password)
                if not is_valid:
                    flash(message, 'error')
                    return redirect(url_for('profile'))
                users[new_username]['password'] = hash_password(new_password)
                flash('Perfil e senha atualizados com sucesso!', 'success')
            else:
                flash('As novas senhas não coincidem. A senha não foi atualizada.', 'error')
        else:
            flash('Perfil atualizado com sucesso!', 'success')

        current_user.id = new_username
        login_user(current_user)

        return redirect(url_for('profile'))

@app.route('/reset', methods=['GET', 'POST'])
def reset():
    if request.method == 'POST':
        email = request.form['email']
        user = next((user for user in users.values() if user['email'] == email), None)
        if user:
            token = generate_token(email)
            reset_url = url_for('reset_with_token', token=token, _external=True)
            subject = "Instruções para redefinir sua senha"
            template = f"Para redefinir sua senha, visite o seguinte link: {reset_url}"
            
            if send_email(email, subject, template):
                flash('Um e-mail com instruções para redefinir sua senha foi enviado.', 'success')
            else:
                flash('Ocorreu um erro ao enviar o e-mail. Por favor, tente novamente.', 'error')
        else:
            flash('E-mail não encontrado.', 'error')
    return render_template('reset.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    email = verify_token(token)
    if not email:
        flash('O link de redefinição de senha é inválido ou expirou.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('As senhas não coincidem.', 'error')
            return render_template('reset_with_token.html')
        
        is_valid, message = validate_password(new_password)
        if not is_valid:
            flash(message, 'error')
            return render_template('reset_with_token.html')
        
        user = next((user for user in users.values() if user['email'] == email), None)
        if user:
            hashed_password = hash_password(new_password)
            user['password'] = hashed_password
            flash('Sua senha foi atualizada com sucesso.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Usuário não encontrado.', 'error')
    
    return render_template('reset_with_token.html')

# Adicione as novas classes e funções para o simulador de mensagens distribuídas

NUM_PROCESSES = 5

class GlobalCounter:
    def __init__(self):
        self.count = 0

    def next(self):
        self.count += 1
        return self.count

class Process:
    def __init__(self, process_id, total_processes):
        self.id = process_id
        self.total_processes = total_processes
        self.message_queues = [[] for _ in range(total_processes)]
        self.delivered_messages = []
        self.processed_messages = []
        self.is_failed = False
        self.failure_duration = 0
        self.recovery_needed = False

    def fail(self, duration=None):
        self.is_failed = True
        self.failure_duration = duration if duration is not None else random.randint(1, 5)
        self.recovery_needed = True

    def recover(self):
        self.is_failed = False
        self.failure_duration = 0
        self.recovery_needed = True

    def generate_message(self):
        if self.is_failed:
            return None
        if random.random() < 0.8:  # 80% chance to generate a message
            message = f"Mensagem do Processo {self.id}: {random.randint(1, 1000)}"
            global_timestamp = global_counter.next()
            return (global_timestamp, self.id, message)
        return None

    def receive_message(self, global_timestamp, sender_id, message):
        self.message_queues[sender_id].append((global_timestamp, message))

    def deliver_messages(self):
        if self.is_failed:
            return []
        delivered = []
        for sender_id in range(self.total_processes):
            while self.message_queues[sender_id]:
                timestamp, message = self.message_queues[sender_id].pop(0)
                delivered_message = f"Emissor {sender_id}: {message}"
                self.delivered_messages.append(delivered_message)
                self.processed_messages.append(delivered_message)
                delivered.append(delivered_message)
        self.recovery_needed = False
        return delivered

    def get_queue_content(self):
        return [f"Emissor {sender_id}: {message}" for sender_id in range(self.total_processes) for _, message in self.message_queues[sender_id]]

    def get_processed_messages(self):
        return self.processed_messages

class PrivilegeBasedAlgorithm:
    def __init__(self, num_processes):
        self.num_processes = num_processes
        self.token_holder = 0
        self.processes = [Process(i, num_processes) for i in range(num_processes)]
        self.global_message_history = []
        self.failure_probability = 0.05  # 5% de chance de falha a cada passo
        self.forced_failure_process = 1  # Processo 1 será forçado a falhar
        self.forced_failure_duration = 2 * num_processes  # Duração da falha forçada (2 rodadas completas)
        self.current_step = 0

    def get_process_status(self):
        return ["Falhou" if process.is_failed else "Ativo" for process in self.processes]
    
    def step(self):
        self.current_step += 1
        failed_processes = []
        recovered_processes = []

        # Forçar falha no processo específico
        if self.current_step == 1:
            self.processes[self.forced_failure_process].fail(self.forced_failure_duration)
            failed_processes.append(self.forced_failure_process)

        for process in self.processes:
            if process.is_failed:
                process.failure_duration -= 1
                if process.failure_duration <= 0:
                    process.recover()
                    recovered_processes.append(process.id)
            elif process.id != self.forced_failure_process and random.random() < self.failure_probability:
                process.fail()
                failed_processes.append(process.id)

        current_process = self.processes[self.token_holder]
        
        while current_process.is_failed:
            self.token_holder = (self.token_holder + 1) % self.num_processes
            current_process = self.processes[self.token_holder]

        new_message = current_process.generate_message()
        message_generated = False
        sent_message = ""

        if new_message:
            self.global_message_history.append(new_message)
            message_generated = True
            sent_message = f"Emissor {new_message[1]}: {new_message[2]}"
            for process in self.processes:
                process.receive_message(*new_message)
        else:
            sent_message = f"Emissor {self.token_holder} não gerou mensagem"

        delivered_messages = []
        for process in self.processes:
            if not process.is_failed:
                delivered = process.deliver_messages()
                delivered_messages.append(delivered)

        receiver_queues = [process.get_queue_content() for process in self.processes]
        processed_messages = [process.get_processed_messages() for process in self.processes]

        self.token_holder = (self.token_holder + 1) % self.num_processes
        while self.processes[self.token_holder].is_failed:
            self.token_holder = (self.token_holder + 1) % self.num_processes

        result = {
            "token_holder": self.token_holder,
            "sent_message": sent_message,
            "receiver_queues": receiver_queues,
            "delivered_messages": delivered_messages,
            "processed_messages": processed_messages,
            "message_generated": message_generated,
            "failed_processes": failed_processes,
            "recovered_processes": recovered_processes,
            "process_status": self.get_process_status()
        }

        return result

global_counter = GlobalCounter()
algorithm = None

# Adicione as novas rotas para o simulador de mensagens distribuídas

@app.route('/distributed-messaging-simulator')
@login_required
def distributed_messaging_simulator():
    if users[current_user.id]['role'] != 'cliente':
        flash('Acesso negado. Esta funcionalidade é apenas para clientes.', 'error')
        return redirect(url_for('dashboard'))
    
    global algorithm, global_counter
    algorithm = PrivilegeBasedAlgorithm(num_processes=NUM_PROCESSES)
    global_counter = GlobalCounter()
    return render_template('distributed-messaging-simulator.html', num_processes=NUM_PROCESSES)

@app.route('/step')
@login_required
def step():
    if users[current_user.id]['role'] != 'cliente':
        return jsonify({"error": "Acesso negado"}), 403
    
    global algorithm
    result = algorithm.step()
    return jsonify(result)

# Atualize a rota do dashboard para incluir a informação sobre o simulador
@app.route('/dashboard')
@login_required
def dashboard():
    user_role = users[current_user.id]['role']
    show_simulator = user_role == 'cliente'
    return render_template('dashboard.html', users=users, show_simulator=show_simulator)

if __name__ == '__main__':
    app.run(debug=True)