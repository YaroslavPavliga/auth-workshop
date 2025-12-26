'EOF'
from flask import Flask, request, jsonify
import os
import jwt
import datetime
from functools import wraps
from dotenv import load_dotenv

# Завантажуємо змінні середовища
load_dotenv()

app = Flask(__name__)

# Секретний ключ для JWT (зберігаємо в .env)
SECRET_KEY = os.getenv('JWT_SECRET', 'dev_secret_change_me_in_production')

# Імітація бази даних користувачів
users = [
    {
        'id': 1,
        'email': 'admin@example.com',
        'password': 'admin123',
        'role': 'admin'
    },
    {
        'id': 2,
        'email': 'user@example.com',
        'password': 'user123',
        'role': 'user'
    }
]

# ========== ДОПОМІЖНІ ФУНКЦІЇ ==========

def find_user(email, password):
    """Знайти користувача за email та паролем"""
    for user in users:
        if user['email'] == email and user['password'] == password:
            return user
    return None

def generate_token(user):
    """Генерувати JWT токен"""
    payload = {
        'sub': user['id'],
        'email': user['email'],
        'role': user['role'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
        'iat': datetime.datetime.utcnow()
    }
    
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def token_required(f):
    """Декоратор для перевірки JWT токена"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Отримуємо токен із заголовка Authorization
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                # Формат: Bearer <token>
                token = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({'error': 'Invalid token format. Use: Bearer <token>'}), 401
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            # Декодуємо токен
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            current_user = {
                'id': data['sub'],
                'email': data['email'],
                'role': data['role']
            }
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        # Додаємо користувача до контексту запиту
        request.current_user = current_user
        return f(*args, **kwargs)
    
    return decorated

def role_required(roles):
    """Декоратор для перевірки ролей"""
    def decorator(f):
        @wraps(f)
        @token_required
        def decorated(*args, **kwargs):
            if request.current_user['role'] not in roles:
                return jsonify({'error': 'Forbidden: insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ========== МАРШРУТИ ==========

@app.route('/login', methods=['POST'])
def login():
    """Аутентифікація користувача та видача JWT токена"""
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password are required'}), 400
    
    # Знаходимо користувача
    user = find_user(data['email'], data['password'])
    
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Генеруємо токен
    token = generate_token(user)
    
    return jsonify({
        'access_token': token,
        'token_type': 'Bearer',
        'expires_in': 900,  # 15 хвилин у секундах
        'user': {
            'id': user['id'],
            'email': user['email'],
            'role': user['role']
        }
    }), 200

@app.route('/profile', methods=['GET'])
@token_required
def profile():
    """Отримання профілю користувача (захищений маршрут)"""
    return jsonify({
        'user_id': request.current_user['id'],
        'email': request.current_user['email'],
        'role': request.current_user['role']
    }), 200

@app.route('/users/<int:user_id>', methods=['DELETE'])
@role_required(['admin'])
def delete_user(user_id):
    """Видалення користувача (тільки для адміністраторів)"""
    return jsonify({
        'message': f'User with ID {user_id} deleted successfully (demo)',
        'deleted_by': request.current_user['email']
    }), 200

@app.route('/admin/dashboard', methods=['GET'])
@role_required(['admin'])
def admin_dashboard():
    """Панель адміністратора (тільки для адмінів)"""
    return jsonify({
        'message': 'Welcome to admin dashboard',
        'admin_info': request.current_user,
        'users_count': len(users),
        'users': users
    }), 200

@app.route('/public', methods=['GET'])
def public_info():
    """Публічна інформація (доступна без аутентифікації)"""
    return jsonify({
        'message': 'This is public information',
        'app': 'JWT Auth Workshop',
        'version': '1.0.0'
    }), 200

@app.route('/user/dashboard', methods=['GET'])
@role_required(['user', 'admin'])
def user_dashboard():
    """Панель користувача (доступна для user та admin)"""
    return jsonify({
        'message': f'Welcome {request.current_user["email"]} to user dashboard',
        'user_info': request.current_user
    }), 200

@app.route('/oauth2/demo', methods=['GET'])
def oauth2_demo():
    """Демонстрація OAuth2 концепції"""
    return jsonify({
        'message': 'OAuth2 Authorization Code Flow Demo',
        'steps': [
            '1. Клієнт перенаправляє користувача до Authorization Server',
            '2. Користувач авторизується та надає згоду',
            '3. Authorization Server повертає authorization code',
            '4. Клієнт обмінює code на access token',
            '5. Клієнт використовує access token для доступу до API'
        ],
        'entities': {
            'resource_owner': 'Користувач',
            'client': 'Веб-додаток',
            'authorization_server': 'Google/Facebook/GitHub',
            'resource_server': 'API що надає дані'
        }
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Перевірка стану сервера"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.datetime.utcnow().isoformat()}), 200

# ========== ОБРОБКА ПОМИЛОК ==========

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# ========== ЗАПУСК СЕРВЕРА ==========

if __name__ == '__main__':
    # У Codespaces потрібно слухати на 0.0.0.0
    app.run(debug=True, port=3000, host='0.0.0.0')
EOF
