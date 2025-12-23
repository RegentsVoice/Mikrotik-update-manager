import os
import sys

#  ЦВЕТА ДЛЯ ТЕРМИНАЛА 
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

#  НАСТРОЙКА ЛОГИРОВАНИЯ 
import warnings
warnings.filterwarnings('ignore')

import logging
logging.getLogger().setLevel(logging.ERROR)
logging.getLogger('werkzeug').setLevel(logging.ERROR)
logging.getLogger('apscheduler').setLevel(logging.ERROR)

#  ИМПОРТЫ 
from flask import Flask
from flask_login import LoginManager
from werkzeug.security import generate_password_hash
from apscheduler.schedulers.background import BackgroundScheduler

from config import config
from database import db, User

#  ФУНКЦИИ ДЛЯ ЦВЕТНОГО ВЫВОДА 
def print_colored_banner():
    """Печать цветного баннера"""
    banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════╗
║  ☕ {Colors.BOLD}MIKROTIK MANAGER v0.9.6.2 {Colors.END}{Colors.CYAN}                       ║
╚══════════════════════════════════════════════════════╝{Colors.END}
"""
    print(banner)

def print_colored_server_info(host, port, env):
    """Цветная информация о сервере"""
    color = Colors.GREEN if env == "DEVELOPMENT" else Colors.YELLOW
    
    info = f"""
{Colors.BLUE}┌──────────────────────────────────────────────────────┐
│  📊 {Colors.BOLD}ИНФОРМАЦИЯ О СЕРВЕРЕ {Colors.END}{Colors.BLUE}                            │
├──────────────────────────────────────────────────────┤
│  🔧 Режим: {color}{env}{Colors.BLUE}
│  🌐 Хост: {Colors.CYAN}{host}{Colors.BLUE}
│  🚪 Порт: {Colors.CYAN}{port}{Colors.BLUE}
│  🗄️ База: {Colors.CYAN}instance/app.db{Colors.BLUE}
└──────────────────────────────────────────────────────┘{Colors.END}

{Colors.GREEN}🚀 СЕРВЕР ЗАПУЩЕН УСПЕШНО!{Colors.END}
{Colors.CYAN}📡 Откройте в браузере: {Colors.BOLD}http://localhost:{port}{Colors.END}
"""
    print(info)

def print_startup_info():
    """Вывод всей информации при запуске"""
    print_colored_banner()
    
    host = app.config.get('HOST', '0.0.0.0')
    port = app.config.get('PORT', 8923)
    env = os.environ.get('FLASK_ENV', 'development').upper()
    
    print_colored_server_info(host, port, env)
    
    # Статистика
    with app.app_context():
        from database import Device, Task, User
        device_count = Device.query.count()
        active_tasks = Task.query.filter_by(is_active=True).count()
        user_count = User.query.count()
        admin_count = User.query.filter_by(role='admin').count()
        
        print(f"{Colors.CYAN}📊 Статистика:{Colors.END}")
        print(f"   📱 Устройств в базе: {Colors.BOLD}{device_count}{Colors.END}")
        print(f"   ⏰ Активных задач: {Colors.BOLD}{active_tasks}{Colors.END}")
        print(f"   👥 Пользователей: {Colors.BOLD}{user_count}{Colors.END}")
        print(f"   👑 Администраторов: {Colors.BOLD}{admin_count}{Colors.END}")
        print()

#  СОЗДАНИЕ ПРИЛОЖЕНИЯ 
app = Flask(__name__, 
           template_folder='templates/html',
           static_folder='templates')
app.config.update(config)

#  ИНИЦИАЛИЗАЦИЯ РАСШИРЕНИЙ 
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#  ПЛАНИРОВЩИК 
scheduler = BackgroundScheduler()
scheduler.start()

#  СОЗДАНИЕ БАЗЫ ДАННЫХ 
with app.app_context():
    db.create_all()
    
    # Проверяем наличие пользователя admin
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin_user = User(
            username='admin',
            password_hash=generate_password_hash('MuMAdm123!'),
            full_name='Администратор Системы',
            email='admin@mikrotik-manager.local',
            role='admin',  # Явно указываем роль администратора
            is_active=True,
            is_admin=True  # Для обратной совместимости
        )
        db.session.add(admin_user)
        db.session.commit()
        print(f"{Colors.GREEN}✅ Создан администратор по умолчанию:{Colors.END}")
        print(f"   👤 Имя пользователя: {Colors.BOLD}admin{Colors.END}")
        print(f"   🔑 Пароль: {Colors.BOLD}MuMAdm123!{Colors.END}")
        print()

#  ИМПОРТ МАРШРУТОВ 
from routes import *

# ЗАПУСК СЕРВЕРА 
if __name__ == '__main__':
    # Выводим информацию
    print_startup_info()
    
    # Настройки
    host = app.config.get('HOST', '0.0.0.0')
    port = app.config.get('PORT', 8923)
    env = os.environ.get('FLASK_ENV', 'development').lower()
    
    # Запуск
    if env == 'production':
        try:
            from waitress import serve
            print(f"{Colors.YELLOW}⚡ Используется Waitress (production сервер){Colors.END}")
            serve(app, host=host, port=port, threads=4)
        except ImportError:
            print(f"{Colors.RED}⚠️  Waitress не установлен, используется Flask сервер{Colors.END}")
            app.run(host=host, port=port, debug=False, use_reloader=False)
    else:
        app.run(
            host=host,
            port=port,
            debug=True,
            use_reloader=False
        )