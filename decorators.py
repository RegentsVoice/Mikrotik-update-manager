from functools import wraps
from flask import abort, flash, redirect, url_for
from flask_login import current_user

def admin_required(f):
    """Декоратор для проверки прав администратора"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Требуется авторизация', 'error')
            return redirect(url_for('login'))
        
        if current_user.role != 'admin' and not current_user.is_admin:
            flash('Доступ запрещен. Требуются права администратора', 'error')
            return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

def manager_or_admin_required(f):
    """Декоратор для проверки прав менеджера или администратора"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Требуется авторизация', 'error')
            return redirect(url_for('login'))
        
        if current_user.role not in ['admin', 'manager'] and not current_user.is_admin:
            flash('Доступ запрещен', 'error')
            return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function