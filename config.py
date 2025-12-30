import os
import sys
import secrets
from datetime import timedelta
from pathlib import Path
import warnings

# Подавление предупреждений о TripleDES
warnings.filterwarnings('ignore', category=DeprecationWarning, module='cryptography')
warnings.filterwarnings('ignore', message='TripleDES has been moved')

def ensure_database_file(db_url):
    """Создает файл базы данных если его не существует"""
    if not db_url.startswith('sqlite:///'):
        return db_url
    
    if db_url == 'sqlite:///:memory:':
        return db_url
    
    # Извлекаем путь к файлу из URL
    file_path = db_url.replace('sqlite:///', '')
    
    # Корректировка пути для Windows
    if sys.platform.startswith('win'):
        if file_path.startswith('/') and len(file_path) > 2 and file_path[2] == ':':
            file_path = file_path[1:]
    else:
        if not file_path.startswith('/'):
            file_path = os.path.join(os.getcwd(), file_path)
    
    # Создаем директорию если ее нет
    db_dir = os.path.dirname(file_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
        print(f"📁 Создана директория: {db_dir}")
    
    # Создаем файл базы данных если его нет
    if not os.path.exists(file_path):
        try:
            with open(file_path, 'w') as f:
                f.write('')
            if not sys.platform.startswith('win'):
                os.chmod(file_path, 0o666)
            print(f"🗃️ Создан фай БД: {file_path}")
        except Exception as e:
            print(f"⚠️Файл БД не создан: {e}")
            return 'sqlite:///:memory:'
    
    return f'sqlite:///{file_path}'

def init_config():
    """Инициализация конфигурации для Windows и Linux"""
    
    # Подавляем предупреждения paramiko
    import paramiko
    import logging
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    
    # Создаем директорию instance
    instance_path = Path('instance')
    instance_path.mkdir(exist_ok=True)
    
    # Путь к .env файлу
    env_path = instance_path / '.env'
    
    # Флаг первого запуска
    first_run = not env_path.exists()
    
    if first_run:
        print("╔══════════════════════════════════════════════════════╗")
        print("║  🚀 ПЕРВЫЙ ЗАПУСК MIKROTIK UPDATE MANAGER            ║")
        print("╚══════════════════════════════════════════════════════╝")
    
    # Определяем путь к базе данных в зависимости от ОС
    if sys.platform.startswith('win') or sys.platform == 'cygwin':
        # Windows: используем абсолютный путь
        db_path = instance_path / 'app.db'
        abs_db_path = db_path.absolute()
        db_url = f'sqlite:///{abs_db_path}'.replace('\\', '/')
        print(f"🪟 Запуск в среде Windows")
    else:
        # Linux/Mac/BSD: используем относительный путь
        db_url = 'sqlite:///instance/app.db'
        print(f"🐧 Запуск в среде Unix")
    
    # Загружаем или создаем .env файл
    if first_run:
        secret_key = secrets.token_hex(32)
        
        env_content = f"""# MikroTik Manager Configuration
# Файл создан автоматически

# Режим работы (production/development)
FLASK_ENV=production

# Секретный ключ для сессий
SECRET_KEY={secret_key}

# Хост и порт для веб-сервера
FLASK_HOST=0.0.0.0
FLASK_PORT=8923

# База данных
DATABASE_URL={db_url}
"""
        
        with open(env_path, 'w', encoding='utf-8') as f:
            f.write(env_content)
        
        print("📁 Создан конфигурационный файл: instance/.env")
        print("🔑 Секретный ключ сгенерирован автоматически")
        
        # Создаем .gitignore в instance
        gitignore_path = instance_path / '.gitignore'
        if not gitignore_path.exists():
            with open(gitignore_path, 'w', encoding='utf-8') as f:
                f.write("*\n!.gitignore\n")
    else:
        # Если .env уже существует, читаем DATABASE_URL из него
        from dotenv import load_dotenv
        load_dotenv(dotenv_path=env_path)
        db_url = os.environ.get('DATABASE_URL', db_url)
    
    # Загружаем переменные окружения из .env
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=env_path)
    
    # Создаем файл базы данных если его нет
    db_url = ensure_database_file(db_url)
    
    # Получаем или генерируем секретный ключ
    secret_key = os.environ.get('SECRET_KEY')
    if not secret_key or secret_key == 'dev-secret-key-change-in-production':
        secret_key = secrets.token_hex(32)
        os.environ['SECRET_KEY'] = secret_key
    
    # Конфигурация приложения
    config = {
        'SECRET_KEY': secret_key,
        'SQLALCHEMY_DATABASE_URI': db_url,
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SESSION_PERMANENT': True,
        'PERMANENT_SESSION_LIFETIME': timedelta(minutes=30),
        'SCHEDULER_API_ENABLED': True,
        'HOST': os.environ.get('FLASK_HOST', '0.0.0.0'),
        'PORT': int(os.environ.get('FLASK_PORT', 8923)),
        'INSTANCE_PATH': str(instance_path.absolute())
    }
    
    return config

# Инициализируем конфигурацию при импорте
config = init_config()

