# routes.py
from app import app, db, login_manager, scheduler
from flask import render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta
import json
import hashlib
import os

from database import User, Device, Task, DeviceLog
from mikrotik_manager import MikroTikManager
from decorators import admin_required, manager_or_admin_required

#  USER LOADER 
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#  АУТЕНТИФИКАЦИЯ 
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            if not user.is_active:
                flash('Пользователь деактивирован', 'error')
                return render_template('login.html')
            
            # Логируем вход
            log = DeviceLog(
                device_id=None,
                action='user_login_success',
                result=json.dumps({
                    'status': 'success',
                    'user_id': user.id,
                    'username': user.username
                }),
                details=f"Пользователь {user.username} вошел в систему",
                performed_by=user.id
            )
            db.session.add(log)
            
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            login_user(user, remember=True)
            flash('Вход выполнен успешно', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Логируем неудачную попытку
            log = DeviceLog(
                device_id=None,
                action='user_login_failed',
                result=json.dumps({
                    'status': 'error',
                    'username': username,
                    'reason': 'invalid_credentials'
                }),
                details=f"Неудачная попытка входа для пользователя {username}",
                performed_by=None
            )
            db.session.add(log)
            db.session.commit()
            
            flash('Неверное имя пользователя или пароль', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log = DeviceLog(
        device_id=None,
        action='user_logout',
        result=json.dumps({
            'status': 'success',
            'user_id': current_user.id,
            'username': current_user.username
        }),
        details=f"Пользователь {current_user.username} вышел из системы",
        performed_by=current_user.id
    )
    db.session.add(log)
    db.session.commit()
    
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('login'))

#  ГЛАВНАЯ 
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

#  УСТРОЙСТВА 
@app.route('/devices')
@manager_or_admin_required
def devices():
    devices_list = Device.query.order_by(Device.name).all()
    return render_template('devices.html', devices=devices_list)

@app.route('/devices/add', methods=['GET', 'POST'])
@manager_or_admin_required
def add_device():
    if request.method == 'POST':
        try:
            existing = Device.query.filter_by(ip_address=request.form.get('ip_address')).first()
            if existing:
                flash('Устройство с таким IP уже существует', 'error')
                return render_template('add_device.html')
            
            device = Device(
                name=request.form.get('name'),
                ip_address=request.form.get('ip_address'),
                port=int(request.form.get('port', 22)),
                username=request.form.get('username'),
                password=request.form.get('password'),
                description=request.form.get('description'),
                created_by=current_user.id
            )
            
            db.session.add(device)
            db.session.commit()
           
            test_result = MikroTikManager.test_connection(device)
            if test_result['status'] == 'success':
                device.status = 'online'
            else:
                device.status = 'offline'
            
            log = DeviceLog(
                device_id=device.id,
                action='device_added',
                result=json.dumps(test_result),
                details=f"Добавлено устройство {device.name} ({device.ip_address})",
                performed_by=current_user.id
            )
            db.session.add(log)
            db.session.commit()
            
            flash('Устройство добавлено', 'success')
            return redirect(url_for('devices'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка: {str(e)}', 'error')
    
    return render_template('add_device.html')

@app.route('/devices/<int:device_id>/edit', methods=['GET', 'POST'])
@manager_or_admin_required
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
            
            log = DeviceLog(
                device_id=device.id,
                action='device_edited',
                result=json.dumps({'status': 'success'}),
                details=f"Изменено устройство {device.name}",
                performed_by=current_user.id
            )
            db.session.add(log)
            db.session.commit()
            
            flash('Устройство обновлено', 'success')
            return redirect(url_for('devices'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка: {str(e)}', 'error')
    
    return render_template('edit_device.html', device=device)

@app.route('/devices/<int:device_id>/delete', methods=['POST'])
@manager_or_admin_required
def delete_device(device_id):
    device = Device.query.get_or_404(device_id)
    
    log = DeviceLog(
        device_id=device.id,
        action='device_deleted',
        result=json.dumps({
            'device_name': device.name,
            'device_ip': device.ip_address
        }),
        details=f"Удалено устройство {device.name}",
        performed_by=current_user.id
    )
    db.session.add(log)
    
    # Удаляем логи устройства
    DeviceLog.query.filter_by(device_id=device_id).delete()
    
    # Удаляем из задач
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

@app.route('/devices/<int:device_id>/test')
@manager_or_admin_required
def test_device_connection(device_id):
    device = Device.query.get_or_404(device_id)
    result = MikroTikManager.test_connection(device)
    
    log = DeviceLog(
        device_id=device.id,
        action='device_test_connection',
        result=json.dumps(result),
        details=f"Тест подключения к {device.name}",
        performed_by=current_user.id
    )
    db.session.add(log)
    
    if result['status'] == 'success':
        device.status = 'online'
        flash('Подключение успешно', 'success')
    else:
        device.status = 'offline'
        flash(f'Ошибка: {result["message"]}', 'error')
    
    db.session.commit()
    return redirect(url_for('devices'))

@app.route('/devices/<int:device_id>/system-info')
@manager_or_admin_required
def get_device_system_info(device_id):
    device = Device.query.get_or_404(device_id)
    result = MikroTikManager.get_extended_system_info(device)
    
    log = DeviceLog(
        device_id=device.id,
        action='device_system_info',
        result=json.dumps({'status': result['status']}),
        details=f"Получение информации о {device.name}",
        performed_by=current_user.id
    )
    db.session.add(log)
    
    if result['status'] == 'success':
        device.firmware_version = result.get('basic', {}).get('version')
        device.status = 'online'
        db.session.commit()
        
        return render_template('system_info.html', 
                             device=device,
                             info=result)
    else:
        device.status = 'offline'
        db.session.commit()
        
        flash(f'Ошибка: {result["message"]}', 'error')
        return redirect(url_for('devices'))

@app.route('/devices/<int:device_id>/check-update')
@manager_or_admin_required
def check_device_update(device_id):
    device = Device.query.get_or_404(device_id)
    result = MikroTikManager.check_for_updates(device)
    
    if result['status'] == 'success':
        device.last_check = datetime.utcnow()
        device.firmware_version = result.get('current_version')
        device.status = 'online'
        
        if result.get('has_updates', False):
            device.needs_update = True
        else:
            device.needs_update = False
        
        log = DeviceLog(
            device_id=device.id,
            action='update_check',
            result=json.dumps({
                'status': 'success',
                'version': result.get('current_version'),
                'has_updates': result.get('has_updates', False)
            }),
            details=f"Проверка обновлений для {device.name}",
            performed_by=current_user.id
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Проверка выполнена', 'success')
    else:
        device.status = 'offline'
        device.needs_update = False
        flash(f'Ошибка: {result["message"]}', 'error')
    
    db.session.commit()
    return redirect(url_for('devices'))

@app.route('/devices/<int:device_id>/perform-update')
@manager_or_admin_required
def perform_device_update(device_id):
    device = Device.query.get_or_404(device_id)
    
    if 'confirmed' not in request.args:
        return render_template('confirm_update.html', device=device)
    
    result = MikroTikManager.perform_update(device)
    
    log = DeviceLog(
        device_id=device.id,
        action='update_performed',
        result=json.dumps({
            'status': result['status'],
            'message': result.get('message', '')
        }),
        details=f"Обновление устройства {device.name}",
        performed_by=current_user.id
    )
    db.session.add(log)
    
    if result['status'] == 'success':
        device.last_update = datetime.utcnow()
        device.needs_update = False
        flash('Обновление выполнено', 'success')
    else:
        flash(f'Ошибка: {result["message"]}', 'error')
    
    db.session.commit()
    return redirect(url_for('devices'))

#  РЕЗЕРВНЫЕ КОПИИ УСТРОЙСТВ 
@app.route('/devices/<int:device_id>/backups')
@manager_or_admin_required
def device_backups(device_id):
    """Страница с резервными копиями устройства"""
    device = Device.query.get_or_404(device_id)
    
    # Получаем список резервных копий с устройства
    result = MikroTikManager.list_backups(device)
    
    if result['status'] == 'success':
        backups = result.get('backups', [])
        total_size = result.get('total_size', 0)
        backup_count = result.get('count', 0)
        
        # Форматируем размер для каждого бэкапа
        for backup in backups:
            size = backup.get('size', 0)
            if size >= 1024*1024*1024:
                backup['size_formatted'] = f"{size/(1024*1024*1024):.1f} GB"
            elif size >= 1024*1024:
                backup['size_formatted'] = f"{size/(1024*1024):.1f} MB"
            elif size >= 1024:
                backup['size_formatted'] = f"{size/1024:.1f} KB"
            else:
                backup['size_formatted'] = f"{size} bytes"
        
        return render_template('device_backups.html',
                             device=device,
                             backups=backups,
                             backup_count=backup_count,
                             total_size=total_size)
    else:
        flash(f'Ошибка при получении резервных копий: {result.get("message", "Неизвестная ошибка")}', 'error')
        return redirect(url_for('devices'))


@app.route('/devices/<int:device_id>/backups/create', methods=['POST'])
@manager_or_admin_required
def create_device_backup(device_id):
    """Создание резервной копии устройства"""
    device = Device.query.get_or_404(device_id)
    
    try:
        result = MikroTikManager.create_backup(device)
        
        if result['status'] == 'success':
            flash(f'Резервная копия создана: {result.get("backup_name")}', 'success')
            
            # Логируем действие
            log = DeviceLog(
                device_id=device.id,
                action='backup_created',
                result=json.dumps({'backup_name': result.get('backup_name')}),
                details=f"Создана резервная копия устройства {device.name}",
                performed_by=current_user.id
            )
            db.session.add(log)
            db.session.commit()
        else:
            flash(f'Ошибка при создании резервной копии: {result.get("message")}', 'error')
    except Exception as e:
        flash(f'Ошибка: {str(e)}', 'error')
    
    return redirect(url_for('device_backups', device_id=device_id))


@app.route('/devices/<int:device_id>/backups/<backup_name>/delete', methods=['POST'])
@manager_or_admin_required
def delete_device_backup(device_id, backup_name):
    """Удаление резервной копии устройства"""
    device = Device.query.get_or_404(device_id)
    
    try:
        result = MikroTikManager.delete_backup(device, backup_name)
        
        if result['status'] == 'success':
            flash(f'Резервная копия удалена: {backup_name}', 'success')
            
            # Логируем действие
            log = DeviceLog(
                device_id=device.id,
                action='backup_deleted',
                result=json.dumps({'backup_name': backup_name}),
                details=f"Удалена резервная копия устройства {device.name}: {backup_name}",
                performed_by=current_user.id
            )
            db.session.add(log)
            db.session.commit()
        else:
            flash(f'Ошибка при удалении резервной копии: {result.get("message")}', 'error')
    except Exception as e:
        flash(f'Ошибка: {str(e)}', 'error')
    
    return redirect(url_for('device_backups', device_id=device_id))

#  МАССОВЫЕ ОПЕРАЦИИ 
@app.route('/batch-check', methods=['GET', 'POST'])
@manager_or_admin_required
def batch_check():
    if request.method == 'GET':
        devices = Device.query.all()
        return render_template('batch_check_form.html', devices=devices, action='check')
    
    device_ids = request.form.getlist('device_ids')
    results = []
    
    for device_id in device_ids:
        device = Device.query.get(device_id)
        if device:
            result = MikroTikManager.check_for_updates(device)
            
            if result['status'] == 'success':
                device.last_check = datetime.utcnow()
                device.firmware_version = result.get('current_version')
                device.status = 'online'
                
                if result.get('has_updates', False):
                    device.needs_update = True
                else:
                    device.needs_update = False
                
                log = DeviceLog(
                    device_id=device.id,
                    action='batch_check',
                    result=json.dumps({
                        'status': 'success',
                        'version': result.get('current_version'),
                        'has_updates': result.get('has_updates', False)
                    }),
                    details=f"Массовая проверка {device.name}",
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
    
    success_count = sum(1 for r in results if r['result']['status'] == 'success')
    error_count = sum(1 for r in results if r['result']['status'] == 'error')
    update_count = sum(1 for r in results if r['result'].get('has_updates', False))
    
    log = DeviceLog(
        device_id=None,
        action='batch_check_completed',
        result=json.dumps({
            'status': 'success',
            'total': len(device_ids),
            'success': success_count,
            'error': error_count,
            'updates': update_count
        }),
        details=f"Массовая проверка завершена. Успешно: {success_count}",
        performed_by=current_user.id
    )
    db.session.add(log)
    db.session.commit()
    
    return render_template('batch_check_results.html', 
                         results=results, 
                         now=datetime.now(),
                         success_count=success_count,
                         error_count=error_count,
                         update_count=update_count,
                         action='check')

@app.route('/batch-update', methods=['GET', 'POST'])
@manager_or_admin_required
def batch_update():
    if request.method == 'GET':
        devices = Device.query.filter_by(needs_update=True).all()
        return render_template('batch_update_form.html', devices=devices, action='update')
    
    device_ids = request.form.getlist('device_ids')
    confirmed = request.form.get('confirmed', False)
    
    if not confirmed:
        devices_to_update = Device.query.filter(Device.id.in_(device_ids)).all()
        return render_template('batch_update_confirm.html', 
                             devices=devices_to_update,
                             device_ids=device_ids)
    
    results = []
    for device_id in device_ids:
        device = Device.query.get(device_id)
        if device:
            result = MikroTikManager.perform_update(device)
            
            if result['status'] == 'success':
                device.last_update = datetime.utcnow()
                device.needs_update = False
                
                log = DeviceLog(
                    device_id=device.id,
                    action='batch_update_performed',
                    result=json.dumps({
                        'status': 'success',
                        'message': result.get('message', '')
                    }),
                    details=f"Массовое обновление {device.name}",
                    performed_by=current_user.id
                )
                db.session.add(log)
            
            results.append({
                'device': device,
                'result': result
            })
    
    db.session.commit()
    
    success_count = sum(1 for r in results if r['result']['status'] == 'success')
    error_count = sum(1 for r in results if r['result']['status'] == 'error')
    
    log = DeviceLog(
        device_id=None,
        action='batch_update_completed',
        result=json.dumps({
            'status': 'success',
            'total': len(device_ids),
            'success': success_count,
            'error': error_count
        }),
        details=f"Массовое обновление завершено. Успешно: {success_count}",
        performed_by=current_user.id
    )
    db.session.add(log)
    db.session.commit()
    
    return render_template('batch_update_results.html', 
                         results=results,
                         now=datetime.now(),
                         success_count=success_count,
                         error_count=error_count)

#  ЗАДАЧИ 
@app.route('/tasks')
@manager_or_admin_required
def tasks():
    tasks_list = Task.query.order_by(Task.created_at.desc()).all()
    return render_template('tasks.html', tasks=tasks_list)

@app.route('/tasks/add', methods=['GET', 'POST'])
@manager_or_admin_required
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
            
            log = DeviceLog(
                device_id=None,
                action='task_created',
                result=json.dumps({
                    'status': 'success',
                    'task_id': task.id,
                    'task_name': task.name,
                    'device_count': len(device_ids)
                }),
                details=f"Создана задача '{task.name}'",
                performed_by=current_user.id
            )
            db.session.add(log)
            db.session.commit()
            
            flash('Задача добавлена', 'success')
            return redirect(url_for('tasks'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка: {str(e)}', 'error')
    
    devices = Device.query.all()
    return render_template('add_task.html', devices=devices)

@app.route('/tasks/<int:task_id>/run-now', methods=['POST'])
@manager_or_admin_required
def run_task_now(task_id):
    task = Task.query.get_or_404(task_id)
    try:
        # Простая имитация выполнения
        log = DeviceLog(
            device_id=None,
            action='task_run_now',
            result=json.dumps({'status': 'success'}),
            details=f"Запущена задача '{task.name}'",
            performed_by=current_user.id
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/tasks/<int:task_id>/<action>', methods=['POST'])
@manager_or_admin_required
def toggle_task_status(task_id, action):
    task = Task.query.get_or_404(task_id)
    
    if action == 'activate':
        task.is_active = True
        message = 'Задача активирована'
    elif action == 'deactivate':
        task.is_active = False
        message = 'Задача деактивирована'
    else:
        return jsonify({'success': False, 'error': 'Неизвестное действие'})
    
    db.session.commit()
    
    log = DeviceLog(
        device_id=None,
        action='task_status_changed',
        result=json.dumps({
            'status': 'success',
            'task_id': task.id,
            'new_status': action
        }),
        details=f"Задача '{task.name}' {message.lower()}",
        performed_by=current_user.id
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'success': True, 'message': message})

@app.route('/tasks/<int:task_id>/details')
@manager_or_admin_required
def task_details(task_id):
    task = Task.query.get_or_404(task_id)
    devices = Device.query.filter(Device.id.in_(task.get_device_ids())).all()
    
    return render_template('task_details.html', task=task, devices=devices)

@app.route('/tasks/<int:task_id>/delete', methods=['POST'])
@manager_or_admin_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    try:
        log = DeviceLog(
            device_id=None,
            action='task_deleted',
            result=json.dumps({
                'status': 'success',
                'task_id': task.id,
                'task_name': task.name
            }),
            details=f"Удалена задача '{task.name}'",
            performed_by=current_user.id
        )
        db.session.add(log)
        
        db.session.delete(task)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

#  ПОЛЬЗОВАТЕЛИ 
@app.route('/users')
@admin_required
def users():
    users_list = User.query.order_by(User.created_at.desc()).all()
    stats = {
        'total_users': User.query.count(),
        'admins_count': User.query.filter_by(role='admin').count(),
        'managers_count': User.query.filter_by(role='manager').count(),
        'inactive_users': User.query.filter_by(is_active=False).count()
    }
    
    return render_template('users.html', 
                         users=users_list, 
                         stats=stats,
                         now=datetime.utcnow())

@app.route('/users/add', methods=['GET', 'POST'])
@admin_required
def add_user():
    if request.method == 'POST':
        try:
            existing_user = User.query.filter_by(username=request.form.get('username')).first()
            if existing_user:
                flash('Пользователь уже существует', 'error')
                return render_template('add_user.html', form_data=request.form)
            
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            if password != confirm_password:
                flash('Пароли не совпадают', 'error')
                return render_template('add_user.html', form_data=request.form)
            
            user = User(
                username=request.form.get('username'),
                password_hash=generate_password_hash(password),
                full_name=request.form.get('full_name'),
                email=request.form.get('email'),
                phone=request.form.get('phone'),
                role=request.form.get('role'),
                is_active=bool(request.form.get('is_active')),
                created_by=current_user.id
            )
            
            db.session.add(user)
            db.session.commit()
            
            log = DeviceLog(
                device_id=None,
                action='user_created',
                result=json.dumps({
                    'status': 'success',
                    'user_id': user.id,
                    'username': user.username,
                    'role': user.role
                }),
                details=f"Создан пользователь {user.username}",
                performed_by=current_user.id
            )
            db.session.add(log)
            db.session.commit()
            
            flash(f'Пользователь {user.username} создан', 'success')
            return redirect(url_for('users'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка: {str(e)}', 'error')
    
    return render_template('add_user.html')

@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    editing_user = User.query.get_or_404(user_id)
    
    # Проверка прав
    if current_user.id != user_id and current_user.role != 'admin':
        flash('Нет прав', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            editing_user.full_name = request.form.get('full_name')
            editing_user.email = request.form.get('email')
            editing_user.phone = request.form.get('phone')
            
            # Только админ может менять роль и статус
            if current_user.role == 'admin' and current_user.id != user_id:
                editing_user.role = request.form.get('role')
                editing_user.is_active = bool(request.form.get('is_active'))
            
            # Смена пароля
            if current_user.id == user_id:
                current_password = request.form.get('current_password')
                new_password = request.form.get('new_password')
                confirm_password = request.form.get('confirm_password')
                
                if new_password:
                    if not current_password or not check_password_hash(editing_user.password_hash, current_password):
                        flash('Неверный пароль', 'error')
                        return render_template('edit_user.html', editing_user=editing_user)
                    
                    if new_password != confirm_password:
                        flash('Пароли не совпадают', 'error')
                        return render_template('edit_user.html', editing_user=editing_user)
                    
                    editing_user.password_hash = generate_password_hash(new_password)
            
            db.session.commit()
            
            log = DeviceLog(
                device_id=None,
                action='user_edited',
                result=json.dumps({'status': 'success'}),
                details=f"Изменен пользователь {editing_user.username}",
                performed_by=current_user.id
            )
            db.session.add(log)
            db.session.commit()
            
            flash('Профиль обновлен', 'success')
            
            if current_user.id == user_id:
                return redirect(url_for('profile'))
            else:
                return redirect(url_for('users'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка: {str(e)}', 'error')
    
    return render_template('edit_user.html', editing_user=editing_user)

@app.route('/users/<int:user_id>/<action>', methods=['POST'])
@admin_required
def toggle_user_status(user_id, action):
    if user_id == current_user.id:
        return jsonify({'success': False, 'error': 'Нельзя изменить статус себе'})
    
    user = User.query.get_or_404(user_id)
    
    if action == 'activate':
        user.is_active = True
        message = 'Пользователь активирован'
    elif action == 'deactivate':
        user.is_active = False
        message = 'Пользователь деактивирован'
    else:
        return jsonify({'success': False, 'error': 'Неизвестное действие'})
    
    try:
        db.session.commit()
        
        log = DeviceLog(
            device_id=None,
            action='user_status_changed',
            result=json.dumps({
                'status': 'success',
                'user_id': user.id,
                'new_status': 'active' if action == 'activate' else 'inactive'
            }),
            details=f"Пользователь {user.username} {message.lower()}",
            performed_by=current_user.id
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({'success': True, 'message': message})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        return jsonify({'success': False, 'error': 'Нельзя удалить себя'})
    
    user = User.query.get_or_404(user_id)
    
    try:
        # Передаем устройства и задачи текущему админу
        Device.query.filter_by(created_by=user_id).update({'created_by': current_user.id})
        Task.query.filter_by(created_by=user_id).update({'created_by': current_user.id})
        
        db.session.delete(user)
        db.session.commit()
        
        log = DeviceLog(
            device_id=None,
            action='user_deleted',
            result=json.dumps({'status': 'success'}),
            details=f"Удален пользователь {user.username}",
            performed_by=current_user.id
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Пользователь удален'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

#  ПРОФИЛЬ 
@app.route('/profile')
@login_required
def profile():
    created_devices_count = Device.query.filter_by(created_by=current_user.id).count()
    created_tasks_count = Task.query.filter_by(created_by=current_user.id).count()
    log_count = DeviceLog.query.filter_by(performed_by=current_user.id).count()
    user_days = (datetime.utcnow() - current_user.created_at).days
    
    user_logs = DeviceLog.query.filter_by(
        performed_by=current_user.id
    ).order_by(DeviceLog.timestamp.desc()).limit(10).all()
    
    return render_template('profile.html',
                         created_devices_count=created_devices_count,
                         created_tasks_count=created_tasks_count,
                         log_count=log_count,
                         user_days=user_days,
                         user_logs=user_logs)

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    try:
        current_user.full_name = request.form.get('full_name')
        current_user.email = request.form.get('email')
        current_user.phone = request.form.get('phone')
        
        # Смена пароля
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        current_password = request.form.get('current_password')
        
        if new_password and confirm_password:
            if new_password != confirm_password:
                flash('Пароли не совпадают', 'error')
                return redirect(url_for('profile'))
            
            if not current_password or not check_password_hash(current_user.password_hash, current_password):
                flash('Неверный текущий пароль', 'error')
                return redirect(url_for('profile'))
            
            current_user.password_hash = generate_password_hash(new_password)
        
        db.session.commit()
        
        log = DeviceLog(
            device_id=None,
            action='profile_updated',
            result=json.dumps({'status': 'success'}),
            details=f"Обновлен профиль {current_user.username}",
            performed_by=current_user.id
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Профиль обновлен', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {str(e)}', 'error')
    
    return redirect(url_for('profile'))

#  ЛОГИ 
@app.route('/logs')
@manager_or_admin_required
def logs():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    query = DeviceLog.query.order_by(DeviceLog.timestamp.desc())
    
    # Фильтры
    search = request.args.get('search', '').strip()
    if search:
        query = query.filter(
            db.or_(
                DeviceLog.details.ilike(f'%{search}%'),
                DeviceLog.action.ilike(f'%{search}%'),
                DeviceLog.result.ilike(f'%{search}%')
            )
        )
    
    action_filter = request.args.get('action', '')
    if action_filter:
        query = query.filter_by(action=action_filter)
    
    user_id = request.args.get('user_id', '', type=str)
    if user_id and user_id.isdigit():
        query = query.filter_by(performed_by=int(user_id))
    
    # Подсчёт старых логов
    month_ago = datetime.utcnow() - timedelta(days=30)
    old_logs_count = DeviceLog.query.filter(DeviceLog.timestamp < month_ago).count()
    
    # Пагинация
    logs_paginated = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Данные для фильтров
    all_users = User.query.order_by(User.username).all()
    action_types = db.session.query(DeviceLog.action).distinct().order_by(DeviceLog.action).all()
    action_types = [a[0] for a in action_types]
    
    return render_template('logs.html',
                         logs=logs_paginated.items,
                         all_users=all_users,
                         action_types=action_types,
                         page=page,
                         total_pages=logs_paginated.pages,
                         total_logs=logs_paginated.total,
                         old_logs_count=old_logs_count)

@app.route('/logs/<int:log_id>/details')
@manager_or_admin_required
def log_details(log_id):
    log = DeviceLog.query.get_or_404(log_id)
    
    formatted_result = None
    if log.result:
        try:
            parsed = json.loads(log.result)
            formatted_result = json.dumps(parsed, indent=2, ensure_ascii=False, default=str)
        except:
            formatted_result = log.result
    
    return render_template('log_details.html',
                         log=log,
                         formatted_result=formatted_result)

@app.route('/logs/<int:log_id>/delete', methods=['POST'])
@admin_required
def delete_log(log_id):
    log = DeviceLog.query.get_or_404(log_id)
    
    try:
        delete_log_entry = DeviceLog(
            device_id=None,
            action='log_deleted',
            result=json.dumps({
                'status': 'success',
                'log_id': log.id,
                'log_action': log.action
            }),
            details=f"Удален лог #{log.id}",
            performed_by=current_user.id
        )
        db.session.add(delete_log_entry)
        
        db.session.delete(log)
        db.session.commit()
        
        flash('Лог удален', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {str(e)}', 'error')
    
    referrer = request.referrer
    if referrer and '/logs' in referrer:
        return redirect(referrer)
    return redirect(url_for('logs'))

@app.route('/logs/clear', methods=['GET', 'POST'])
@admin_required
def clear_logs():
    if request.method == 'GET':
        month_ago = datetime.utcnow() - timedelta(days=30)
        old_logs_count = DeviceLog.query.filter(DeviceLog.timestamp < month_ago).count()
        return render_template('confirm_clear_logs.html', old_logs_count=old_logs_count)
    
    month_ago = datetime.utcnow() - timedelta(days=30)
    
    try:
        old_logs = DeviceLog.query.filter(DeviceLog.timestamp < month_ago).all()
        deleted_count = len(old_logs)
        
        if deleted_count == 0:
            flash('Нет старых логов', 'info')
            return redirect(url_for('logs'))
        
        log_entry = DeviceLog(
            device_id=None,
            action='logs_cleared',
            result=json.dumps({
                'deleted_count': deleted_count,
                'older_than': month_ago.isoformat()
            }),
            details=f"Очищено {deleted_count} старых логов",
            performed_by=current_user.id
        )
        db.session.add(log_entry)
        
        DeviceLog.query.filter(DeviceLog.timestamp < month_ago).delete()
        db.session.commit()
        
        flash(f'Очищено {deleted_count} логов', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {str(e)}', 'error')
    
    return redirect(url_for('logs'))

@app.route('/logs/delete-all', methods=['GET', 'POST'])
@admin_required
def delete_all_logs():
    if request.method == 'GET':
        total_logs = DeviceLog.query.count()
        return render_template('confirm_delete_all.html', total_logs=total_logs)
    
    try:
        total_logs = DeviceLog.query.count()
        
        if total_logs == 0:
            flash('Нет логов', 'info')
            return redirect(url_for('logs'))
        
        log_entry = DeviceLog(
            device_id=None,
            action='all_logs_deleted',
            result=json.dumps({'total_deleted': total_logs}),
            details=f"Удалены все логи ({total_logs} записей)",
            performed_by=current_user.id
        )
        db.session.add(log_entry)
        
        DeviceLog.query.delete()
        db.session.commit()
        
        flash(f'Удалено {total_logs} логов', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка: {str(e)}', 'error')
    
    return redirect(url_for('logs'))

#  API 
@app.route('/api/device/<int:device_id>/status')
@manager_or_admin_required
def device_status(device_id):
    device = Device.query.get_or_404(device_id)
    result = MikroTikManager.test_connection(device)
    
    log = DeviceLog(
        device_id=device.id,
        action='device_status_api',
        result=json.dumps({'status': result['status']}),
        details=f"API запрос статуса {device.name}",
        performed_by=current_user.id
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify(result)

@app.route('/api/users')
@login_required
def get_users_api():
    users = User.query.order_by(User.username).all()
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'role': user.role
    } for user in users])

#  СИСТЕМНАЯ ИНФОРМАЦИЯ 
@app.route('/devices/<int:device_id>/debug')
@manager_or_admin_required
def debug_device_connection(device_id):
    """Расширенная диагностика подключения устройства"""
    device = Device.query.get_or_404(device_id)
    
    try:
        # Пробуем подключиться с детальной информацией
        ssh = MikroTikManager.connect_to_device(device)
        if ssh:
            # Получаем детальную информацию
            system_result = MikroTikManager.execute_command(ssh, '/system resource print')
            identity_result = MikroTikManager.execute_command(ssh, '/system identity print')
            
            MikroTikManager._safe_close(ssh)
            
            debug_info = {
                'status': 'success',
                'system_info': system_result,
                'identity_info': identity_result,
                'message': 'Подключение успешно'
            }
        else:
            debug_info = {
                'status': 'error',
                'message': 'Не удалось установить SSH соединение'
            }
    except Exception as e:
        debug_info = {
            'status': 'error',
            'message': f'Исключение: {str(e)}'
        }
    
    log = DeviceLog(
        device_id=device.id,
        action='device_debug_connection',
        result=json.dumps({'status': debug_info['status']}),
        details=f"Диагностика подключения к {device.name}",
        performed_by=current_user.id
    )
    db.session.add(log)
    db.session.commit()
    
    return render_template('debug_connection.html',
                         device=device,
                         debug_info=debug_info)

#  ВСПОМОГАТЕЛЬНЫЕ 
@app.context_processor
def utility_processor():
    def from_json(json_str):
        try:
            if json_str:
                return json.loads(json_str)
        except:
            pass
        return {}
    
    def tojson(obj, indent=2):
        try:
            return json.dumps(obj, indent=indent, ensure_ascii=False, default=str)
        except:
            return str(obj)
    
    def csrf_token():
        if 'csrf_token' not in session:
            session['csrf_token'] = hashlib.sha256(os.urandom(60)).hexdigest()
        return session['csrf_token']
    
    return dict(from_json=from_json, tojson=tojson, csrf_token=csrf_token)

#  ОШИБКИ 
@app.errorhandler(404)
def page_not_found(e):
    if current_user.is_authenticated:
        return render_template('404.html'), 404
    else:
        return redirect(url_for('login'))

@app.errorhandler(500)
def internal_server_error(e):
    if current_user.is_authenticated:
        return render_template('500.html'), 500
    else:
        return redirect(url_for('login'))

#  ТЕСТ 
@app.route('/test')
def test():
    return 'OK'

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'timestamp': datetime.utcnow().isoformat()})

#  ИНИЦИАЛИЗАЦИЯ 
with app.app_context():
    try:
        db.create_all()
    except Exception as e:
        print(f"Ошибка инициализации БД: {e}")