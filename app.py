from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import paramiko
import json
from datetime import datetime, timedelta
import traceback
import logging
import re

from config import Config
from database import db, User, Device, Task, DeviceLog
from mikrotik_manager import MikroTikManager

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)

# Инициализация расширений
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Инициализация планировщика
scheduler = BackgroundScheduler(daemon=True)
scheduler.start()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Создание таблиц и начального пользователя
with app.app_context():
    db.create_all()
    # Создаем администратора по умолчанию, если его нет
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password_hash=generate_password_hash('admin'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

# Маршруты аутентификации
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user, remember=True)
            flash('Вход выполнен успешно!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Неверное имя пользователя или пароль', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    stats = {
        'total_devices': Device.query.count(),
        'online_devices': Device.query.filter_by(status='online').count(),
        'pending_updates': Device.query.filter_by(needs_update=True).count(),
        'active_tasks': Task.query.filter_by(is_active=True).count()
    }
    
    recent_logs = DeviceLog.query.order_by(DeviceLog.timestamp.desc()).limit(5).all()
    all_devices = Device.query.all()
    
    return render_template('dashboard.html', 
                         stats=stats, 
                         recent_logs=recent_logs,
                         all_devices=all_devices)

@app.route('/devices')
@login_required
def devices():
    devices_list = Device.query.order_by(Device.name).all()
    return render_template('devices.html', devices=devices_list)

@app.route('/devices/add', methods=['GET', 'POST'])
@login_required
def add_device():
    if request.method == 'POST':
        try:
            # Проверяем, существует ли уже устройство с таким IP
            existing = Device.query.filter_by(ip_address=request.form.get('ip_address')).first()
            if existing:
                flash('Устройство с таким IP адресом уже существует!', 'error')
                return render_template('add_device.html')
            
            device = Device(
                name=request.form.get('name'),
                ip_address=request.form.get('ip_address'),
                port=int(request.form.get('port', 22)),
                username=request.form.get('username'),
                password=request.form.get('password'),
                description=request.form.get('description'),
                is_encrypted=False
            )
            
            db.session.add(device)
            db.session.commit()
            
            # Тестируем подключение
            test_result = MikroTikManager.test_connection(device)
            if test_result['status'] == 'success':
                device.status = 'online'
            else:
                device.status = 'offline'
            
            # Логируем действие
            log = DeviceLog(
                device_id=device.id,
                action='device_added',
                result=json.dumps(test_result),
                performed_by=current_user.id
            )
            db.session.add(log)
            db.session.commit()
            
            flash('Устройство успешно добавлено!', 'success')
            return redirect(url_for('devices'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при добавлении устройства: {str(e)}', 'error')
    
    return render_template('add_device.html')


# Маршруты для управления бэкапами
@app.route('/devices/<int:device_id>/backups')
@login_required
def device_backups(device_id):
    """Просмотр резервных копий устройства"""
    device = Device.query.get_or_404(device_id)
    
    result = MikroTikManager.list_backups(device)
    
    if result['status'] == 'success':
        return render_template('device_backups.html', 
                             device=device,
                             backups=result.get('backups', []),
                             backup_count=result.get('count', 0))
    else:
        flash(f'Ошибка получения бэкапов: {result["message"]}', 'error')
        return redirect(url_for('get_device_system_info', device_id=device_id))

@app.route('/devices/<int:device_id>/create-backup', methods=['POST'])
@login_required
def create_device_backup(device_id):
    """Создание резервной копии устройства"""
    device = Device.query.get_or_404(device_id)
    
    result = MikroTikManager.create_backup(device)
    
    if result['status'] == 'success':
        flash(f'Резервная копия создана: {result.get("backup_name", "")}', 'success')
    else:
        flash(f'Ошибка создания бэкапа: {result["message"]}', 'error')
    
    return redirect(url_for('device_backups', device_id=device_id))

@app.route('/devices/<int:device_id>/delete-backup/<backup_name>', methods=['POST'])
@login_required
def delete_device_backup(device_id, backup_name):
    """Удаление резервной копии"""
    device = Device.query.get_or_404(device_id)
    
    result = MikroTikManager.delete_backup(device, backup_name)
    
    if result['status'] == 'success':
        flash(f'Резервная копия удалена: {backup_name}', 'success')
    else:
        flash(f'Ошибка удаления бэкапа: {result["message"]}', 'error')
    
    return redirect(url_for('device_backups', device_id=device_id))

@app.route('/devices/<int:device_id>/cleanup-backups', methods=['POST'])
@login_required
def cleanup_device_backups(device_id):
    """Очистка старых резервных копий"""
    device = Device.query.get_or_404(device_id)
    
    result = MikroTikManager.delete_old_backups(device, keep_count=5)
    
    if result['status'] == 'success':
        deleted_count = len(result.get('deleted', []))
        flash(f'Удалено {deleted_count} старых бэкапов', 'success')
    else:
        flash(f'Ошибка очистки бэкапов: {result["message"]}', 'error')
    
    return redirect(url_for('device_backups', device_id=device_id))

# Маршрут для обновления устройства с поддержкой бэкапа
@app.route('/devices/<int:device_id>/perform-update')
@login_required
def perform_device_update(device_id):
    device = Device.query.get_or_404(device_id)
    
    # Подтверждение
    if 'confirmed' not in request.args:
        return render_template('confirm_update.html', device=device)
    
    # Проверяем, нужно ли создавать бэкап
    create_backup = request.args.get('backup', 'true').lower() == 'true'
    
    # Используем метод с бэкапом
    if create_backup:
        result = MikroTikManager.perform_update_with_backup(device, create_backup=True)
    else:
        result = MikroTikManager.perform_update(device)
    
    if result['status'] == 'success':
        device.last_update = datetime.utcnow()
        device.needs_update = False
        
        # Логируем действие
        log = DeviceLog(
            device_id=device.id,
            action='update_performed',
            result=json.dumps({
                'status': 'success',
                'with_backup': create_backup,
                'message': result.get('message', '')
            }),
            performed_by=current_user.id
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Обновление выполнено успешно! Устройство будет перезагружено.', 'success')
    else:
        flash(f'Ошибка: {result["message"]}', 'error')
    
    db.session.commit()
    return redirect(url_for('devices'))

@app.route('/devices/<int:device_id>/test')
@login_required
def test_device_connection(device_id):
    device = Device.query.get_or_404(device_id)
    result = MikroTikManager.test_connection(device)
    
    if result['status'] == 'success':
        # При успешном тесте получаем полную информацию
        system_info = MikroTikManager.get_system_info(device)
        
        if system_info['status'] == 'success':
            device.status = 'online'
            device.firmware_version = system_info.get('version')
            flash(f'Подключение успешно! Версия RouterOS: {system_info.get("version")}', 'success')
        else:
            device.status = 'online'
            flash('Подключение успешно, но не удалось получить версию', 'warning')
    else:
        device.status = 'offline'
        flash(f'Ошибка подключения: {result["message"]}', 'error')
    
    db.session.commit()
    return redirect(url_for('devices'))

@app.route('/devices/<int:device_id>/system-info')
@login_required
def get_device_system_info(device_id):
    """Получение подробной информации о системе устройства"""
    device = Device.query.get_or_404(device_id)
    
    result = MikroTikManager.get_system_info(device)
    
    if result['status'] == 'success':
        device.firmware_version = result.get('version')
        device.status = 'online'
        db.session.commit()
        
        return render_template('system_info.html', 
                             device=device,
                             info=result)
    else:
        device.status = 'offline'
        db.session.commit()
        
        flash(f'Ошибка получения информации: {result["message"]}', 'error')
        return redirect(url_for('devices'))

@app.route('/devices/<int:device_id>/check-update')
@login_required
def check_device_update(device_id):
    device = Device.query.get_or_404(device_id)
    result = MikroTikManager.check_for_updates(device)
    
    if result['status'] == 'success':
        device.last_check = datetime.utcnow()
        device.firmware_version = result.get('current_version')
        device.status = 'online'
        
        # Определяем, нужны ли обновления
        if result.get('has_updates', False):
            device.needs_update = True
            update_status = 'available'
        else:
            device.needs_update = False
            update_status = 'latest'
        
        # Логируем действие
        log = DeviceLog(
            device_id=device.id,
            action='update_check',
            result=json.dumps({
                'status': 'success',
                'version': result.get('current_version'),
                'update_status': update_status,
                'has_updates': result.get('has_updates', False)
            }),
            performed_by=current_user.id
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Проверка обновлений выполнена успешно!', 'success')
    else:
        device.status = 'offline'
        device.needs_update = False
        flash(f'Ошибка: {result["message"]}', 'error')
    
    db.session.commit()
    return redirect(url_for('devices'))

# МАССОВАЯ ПРОВЕРКА ОБНОВЛЕНИЙ
@app.route('/batch-update-check', methods=['GET', 'POST'])
@login_required
def batch_update_check():
    """Массовая проверка обновлений (для совместимости со старыми шаблонами)"""
    if request.method == 'GET':
        # Показываем форму выбора устройств для проверки
        devices = Device.query.all()
        return render_template('batch_check_form.html', devices=devices)
    
    # POST запрос - выполнение проверки
    device_ids = request.form.getlist('device_ids')
    results = []
    
    for device_id in device_ids:
        device = Device.query.get(device_id)
        if device:
            result = MikroTikManager.check_for_updates(device)
            
            # Обновляем статус устройства
            if result['status'] == 'success':
                device.last_check = datetime.utcnow()
                device.firmware_version = result.get('current_version')
                device.status = 'online'
                
                # Определяем, нужны ли обновления
                if result.get('has_updates', False):
                    device.needs_update = True
                else:
                    device.needs_update = False
                
                # Логируем действие
                log = DeviceLog(
                    device_id=device.id,
                    action='batch_update_check',
                    result=json.dumps({
                        'status': 'success',
                        'version': result.get('current_version'),
                        'has_updates': result.get('has_updates', False)
                    }),
                    performed_by=current_user.id
                )
                db.session.add(log)
            else:
                device.status = 'offline'
                device.needs_update = False
            
            results.append({
                'device': device,
                'result': result
            })
    
    db.session.commit()
    
    # Считаем статистику
    success_count = sum(1 for r in results if r['result']['status'] == 'success')
    error_count = sum(1 for r in results if r['result']['status'] == 'error')
    update_count = sum(1 for r in results if r['result'].get('has_updates', False))
    
    return render_template('batch_check_results.html', 
                         results=results, 
                         now=datetime.now(),
                         success_count=success_count,
                         error_count=error_count,
                         update_count=update_count,
                         action='check')

# МАССОВОЕ ОБНОВЛЕНИЕ
@app.route('/batch-update', methods=['GET', 'POST'])
@login_required
def batch_update():
    if request.method == 'GET':
        # Показываем форму выбора устройств для обновления
        # Показываем только устройства, которые требуют обновления
        devices = Device.query.filter_by(needs_update=True).all()
        
        if not devices:
            flash('Нет устройств, требующих обновления', 'info')
            return redirect(url_for('devices'))
        
        return render_template('batch_update_form.html', devices=devices, action='update')
    
    # POST запрос - выполнение обновления
    device_ids = request.form.getlist('device_ids')
    
    # Проверяем, нужно ли создавать бэкап
    create_backup = request.form.get('create_backup', 'true').lower() == 'true'
    
    # Получаем подтверждение
    confirmed = request.form.get('confirmed', False)
    
    if not confirmed:
        # Показываем подтверждение
        devices_to_update = Device.query.filter(Device.id.in_(device_ids)).all()
        return render_template('batch_update_confirm.html', 
                             devices=devices_to_update,
                             device_ids=device_ids,
                             create_backup=create_backup)
    
    # Выполняем обновление
    results = []
    for device_id in device_ids:
        device = Device.query.get(device_id)
        if device:
            # Используем метод с бэкапом если нужно
            if create_backup:
                result = MikroTikManager.perform_update_with_backup(device, create_backup=True)
            else:
                result = MikroTikManager.perform_update(device)
            
            if result['status'] == 'success':
                device.last_update = datetime.utcnow()
                device.needs_update = False
                
                # Логируем действие
                log = DeviceLog(
                    device_id=device.id,
                    action='batch_update_performed',
                    result=json.dumps({
                        'status': 'success',
                        'with_backup': create_backup,
                        'message': result.get('message', '')
                    }),
                    performed_by=current_user.id
                )
                db.session.add(log)
            
            results.append({
                'device': device,
                'result': result
            })
    
    db.session.commit()
    
    # Считаем статистику
    success_count = sum(1 for r in results if r['result']['status'] == 'success')
    error_count = sum(1 for r in results if r['result']['status'] == 'error')
    
    return render_template('batch_update_results.html', 
                         results=results,
                         now=datetime.now(),
                         success_count=success_count,
                         error_count=error_count,
                         with_backup=create_backup)

# МАССОВАЯ ПРОВЕРКА (альтернативный маршрут)
@app.route('/batch-check', methods=['GET', 'POST'])
@login_required
def batch_check():
    """Альтернативный маршрут для массовой проверки"""
    if request.method == 'GET':
        # Показываем форму выбора устройств для проверки
        devices = Device.query.all()
        return render_template('batch_check_form.html', devices=devices, action='check')
    
    # POST запрос - выполнение проверки
    device_ids = request.form.getlist('device_ids')
    results = []
    
    for device_id in device_ids:
        device = Device.query.get(device_id)
        if device:
            result = MikroTikManager.check_for_updates(device)
            
            # Обновляем статус устройства
            if result['status'] == 'success':
                device.last_check = datetime.utcnow()
                device.firmware_version = result.get('current_version')
                device.status = 'online'
                
                # Определяем, нужны ли обновления
                if result.get('has_updates', False):
                    device.needs_update = True
                else:
                    device.needs_update = False
                
                # Логируем действие
                log = DeviceLog(
                    device_id=device.id,
                    action='batch_check',
                    result=json.dumps({
                        'status': 'success',
                        'version': result.get('current_version'),
                        'has_updates': result.get('has_updates', False)
                    }),
                    performed_by=current_user.id
                )
                db.session.add(log)
            else:
                device.status = 'offline'
                device.needs_update = False
            
            results.append({
                'device': device,
                'result': result
            })
    
    db.session.commit()
    
    # Считаем статистику
    success_count = sum(1 for r in results if r['result']['status'] == 'success')
    error_count = sum(1 for r in results if r['result']['status'] == 'error')
    update_count = sum(1 for r in results if r['result'].get('has_updates', False))
    
    return render_template('batch_check_results.html', 
                         results=results, 
                         now=datetime.now(),
                         success_count=success_count,
                         error_count=error_count,
                         update_count=update_count,
                         action='check')

@app.route('/tasks')
@login_required
def tasks():
    tasks_list = Task.query.order_by(Task.created_at.desc()).all()
    return render_template('tasks.html', tasks=tasks_list)

@app.route('/tasks/add', methods=['GET', 'POST'])
@login_required
def add_task():
    if request.method == 'POST':
        try:
            device_ids = request.form.getlist('device_ids')
            
            task = Task(
                name=request.form.get('name'),
                task_type=request.form.get('task_type'),
                command=request.form.get('command', ''),
                cron_expression=request.form.get('cron_expression'),
                is_active=bool(request.form.get('is_active')),
                created_by=current_user.id
            )
            task.set_device_ids([int(id) for id in device_ids])
            
            db.session.add(task)
            db.session.commit()
            
            # Если задача активна, добавляем в планировщик
            if task.is_active and task.cron_expression:
                schedule_task(task)
            
            flash('Задача успешно добавлена!', 'success')
            return redirect(url_for('tasks'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при добавлении задачи: {str(e)}', 'error')
    
    devices = Device.query.all()
    return render_template('add_task.html', devices=devices)

def schedule_task(task):
    """Добавление задачи в планировщик"""
    def task_wrapper():
        with app.app_context():
            execute_task(task.id)
    
    if task.cron_expression:
        try:
            trigger = CronTrigger.from_crontab(task.cron_expression)
            scheduler.add_job(
                func=task_wrapper,
                trigger=trigger,
                id=f'task_{task.id}',
                replace_existing=True,
                misfire_grace_time=60
            )
            logger.info(f"Scheduled task {task.id} with cron {task.cron_expression}")
        except Exception as e:
            logger.error(f"Error scheduling task {task.id}: {str(e)}")

def execute_task(task_id):
    """Выполнение запланированной задачи"""
    task = Task.query.get(task_id)
    if not task or not task.is_active:
        return
    
    results = []
    device_ids = task.get_device_ids()
    
    for device_id in device_ids:
        device = Device.query.get(device_id)
        if device:
            if task.task_type == 'check_update':
                result = MikroTikManager.check_for_updates(device)
            elif task.task_type == 'perform_update':
                result = MikroTikManager.perform_update(device)
            elif task.task_type == 'custom_command' and task.command:
                ssh = MikroTikManager.connect_to_device(device)
                if ssh:
                    cmd_result = MikroTikManager.execute_command(ssh, task.command)
                    ssh.close()
                    result = {'status': 'success' if cmd_result['success'] else 'error', 
                             'output': cmd_result.get('output', cmd_result.get('error'))}
                else:
                    result = {'status': 'error', 'message': 'Connection failed'}
            else:
                result = {'status': 'error', 'message': 'Unknown task type'}
            
            results.append({
                'device': device.name,
                'result': result
            })
            
            # Логируем действие
            log = DeviceLog(
                device_id=device.id,
                action=f'task_{task.task_type}',
                result=json.dumps(result),
                performed_by=task.created_by
            )
            db.session.add(log)
    
    task.last_run = datetime.utcnow()
    task.last_result = json.dumps(results)
    db.session.commit()

@app.route('/tasks/<int:task_id>/run-now', methods=['POST'])
@login_required
def run_task_now(task_id):
    task = Task.query.get_or_404(task_id)
    try:
        execute_task(task_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/tasks/<int:task_id>/<action>', methods=['POST'])
@login_required
def toggle_task_status(task_id, action):
    task = Task.query.get_or_404(task_id)
    
    if action == 'activate':
        task.is_active = True
        if task.cron_expression:
            schedule_task(task)
    elif action == 'deactivate':
        task.is_active = False
        try:
            scheduler.remove_job(f'task_{task.id}')
        except:
            pass
    
    db.session.commit()
    return jsonify({'success': True})

@app.route('/tasks/<int:task_id>/details')
@login_required
def task_details(task_id):
    task = Task.query.get_or_404(task_id)
    devices = Device.query.filter(Device.id.in_(task.get_device_ids())).all()
    
    return render_template('task_details.html', task=task, devices=devices)

@app.route('/tasks/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    try:
        # Удаляем задачу из планировщика
        try:
            scheduler.remove_job(f'task_{task.id}')
        except:
            pass
        
        # Удаляем задачу из БД
        db.session.delete(task)
        db.session.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/logs')
@login_required
def logs():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    logs_query = DeviceLog.query.order_by(DeviceLog.timestamp.desc())
    logs_paginated = logs_query.paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('logs.html', 
                         logs=logs_paginated.items,
                         page=page,
                         total_pages=logs_paginated.pages)

@app.route('/logs/<int:log_id>/details')
@login_required
def log_details(log_id):
    log = DeviceLog.query.get_or_404(log_id)
    return render_template('log_details.html', log=log)

@app.route('/logs/clear', methods=['POST'])
@login_required
def clear_logs():
    if current_user.is_admin:
        # Удаляем только старые логи (старше 30 дней)
        month_ago = datetime.utcnow() - timedelta(days=30)
        DeviceLog.query.filter(DeviceLog.timestamp < month_ago).delete()
        db.session.commit()
        flash('Старые логи очищены', 'success')
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Требуются права администратора'})

# API endpoint для проверки состояния
@app.route('/api/device/<int:device_id>/status')
@login_required
def device_status(device_id):
    device = Device.query.get_or_404(device_id)
    result = MikroTikManager.test_connection(device)
    return jsonify(result)

# Удаление устройства
@app.route('/devices/<int:device_id>/delete', methods=['POST'])
@login_required
def delete_device(device_id):
    device = Device.query.get_or_404(device_id)
    
    # Удаляем связанные логи
    DeviceLog.query.filter_by(device_id=device_id).delete()
    
    # Удаляем устройство из задач
    tasks = Task.query.all()
    for task in tasks:
        device_ids = task.get_device_ids()
        if device_id in device_ids:
            device_ids.remove(device_id)
            task.set_device_ids(device_ids)
    
    db.session.delete(device)
    db.session.commit()
    
    flash('Устройство удалено', 'success')
    return redirect(url_for('devices'))

# Редактирование устройства
@app.route('/devices/<int:device_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_device(device_id):
    device = Device.query.get_or_404(device_id)
    
    if request.method == 'POST':
        try:
            device.name = request.form.get('name')
            device.ip_address = request.form.get('ip_address')
            device.port = int(request.form.get('port', 22))
            device.username = request.form.get('username')
            device.password = request.form.get('password')
            device.description = request.form.get('description')
            
            db.session.commit()
            
            # Логируем действие
            log = DeviceLog(
                device_id=device.id,
                action='device_edited',
                result='Device updated successfully',
                performed_by=current_user.id
            )
            db.session.add(log)
            db.session.commit()
            
            flash('Устройство обновлено!', 'success')
            return redirect(url_for('devices'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при обновлении устройства: {str(e)}', 'error')
    
    return render_template('edit_device.html', device=device)

@app.route('/devices/<int:device_id>/debug')
@login_required
def debug_device_connection(device_id):
    """Отладка подключения к устройству"""
    device = Device.query.get_or_404(device_id)
    
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        debug_info = {
            'device': {
                'name': device.name,
                'ip': device.ip_address,
                'port': device.port,
                'username': device.username
            },
            'steps': []
        }
        
        # Шаг 1: Попытка подключения
        debug_info['steps'].append({
            'step': 'Подключение',
            'action': f'Попытка подключиться к {device.ip_address}:{device.port}'
        })
        
        client.connect(
            hostname=device.ip_address,
            port=device.port,
            username=device.username,
            password=device.password,
            timeout=10,
            banner_timeout=15,
            auth_timeout=10
        )
        
        debug_info['steps'].append({
            'step': 'Подключение',
            'result': 'Успешно',
            'details': 'SSH подключение установлено'
        })
        
        # Шаг 2: Выполнение простой команды
        debug_info['steps'].append({
            'step': 'Тестовая команда',
            'action': 'Выполнение команды: /system identity print'
        })
        
        stdin, stdout, stderr = client.exec_command('/system identity print')
        identity_output = stdout.read().decode('utf-8', errors='ignore')
        error_output = stderr.read().decode('utf-8', errors='ignore')
        
        debug_info['steps'].append({
            'step': 'Тестовая команда',
            'result': 'Успешно' if not error_output else 'Ошибка',
            'output': identity_output[:200],
            'error': error_output
        })
        
        # Шаг 3: Получение информации о системе
        debug_info['steps'].append({
            'step': 'Информация о системе',
            'action': 'Выполнение команды: /system resource print'
        })
        
        stdin, stdout, stderr = client.exec_command('/system resource print')
        resource_output = stdout.read().decode('utf-8', errors='ignore')
        resource_error = stderr.read().decode('utf-8', errors='ignore')
        
        debug_info['steps'].append({
            'step': 'Информация о системе',
            'result': 'Успешно' if not resource_error else 'Ошибка',
            'output': resource_output,
            'error': resource_error
        })
        
        # Шаг 4: Получение информации о пакетах
        debug_info['steps'].append({
            'step': 'Информация о пакетах',
            'action': 'Выполнение команды: /system package print'
        })
        
        stdin, stdout, stderr = client.exec_command('/system package print')
        package_output = stdout.read().decode('utf-8', errors='ignore')
        package_error = stderr.read().decode('utf-8', errors='ignore')
        
        debug_info['steps'].append({
            'step': 'Информация о пакетах',
            'result': 'Успешно' if not package_error else 'Ошибка',
            'output': package_output,
            'error': package_error
        })
        
        client.close()
        
        return render_template('debug_connection.html', 
                             debug_info=debug_info,
                             device=device)
        
    except paramiko.AuthenticationException as e:
        debug_info['steps'].append({
            'step': 'Подключение',
            'result': 'Ошибка аутентификации',
            'details': str(e)
        })
    except paramiko.SSHException as e:
        debug_info['steps'].append({
            'step': 'Подключение',
            'result': 'Ошибка SSH',
            'details': str(e)
        })
    except Exception as e:
        debug_info['steps'].append({
            'step': 'Подключение',
            'result': 'Общая ошибка',
            'details': str(e),
            'traceback': traceback.format_exc()
        })
    
    return render_template('debug_connection.html', 
                         debug_info=debug_info,
                         device=device)

# Обработчики ошибок
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    # При старте приложения планируем все активные задачи
    with app.app_context():
        active_tasks = Task.query.filter_by(is_active=True).all()
        for task in active_tasks:
            if task.cron_expression:
                schedule_task(task)
    
    app.run(debug=True, host='0.0.0.0', port=5000)