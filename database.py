from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import json

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    role = db.Column(db.String(20), default='manager')  # admin или manager
    full_name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Для обратной совместимости
    is_admin = db.Column(db.Boolean, default=False)
    
    # Внешний ключ для создателя
    creator = db.relationship('User', remote_side=[id], 
                            backref='created_users',
                            uselist=False)
    
    # Свойство для удобного доступа к is_admin через role
    @property
    def is_admin_property(self):
        return self.role == 'admin'
    
    @is_admin_property.setter
    def is_admin_property(self, value):
        if value:
            self.role = 'admin'
            self.is_admin = True
        elif self.role == 'admin':
            self.role = 'manager'
            self.is_admin = False

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    port = db.Column(db.Integer, default=22)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_encrypted = db.Column(db.Boolean, default=False)
    ssh_key = db.Column(db.Text, nullable=True)
    description = db.Column(db.Text)
    last_check = db.Column(db.DateTime)
    last_update = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='unknown')
    firmware_version = db.Column(db.String(50))
    needs_update = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Кто создал устройство
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    creator = db.relationship('User', backref='created_devices')

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    device_ids = db.Column(db.Text)
    task_type = db.Column(db.String(50), nullable=False)
    command = db.Column(db.Text)
    cron_expression = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    last_run = db.Column(db.DateTime)
    last_result = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    creator = db.relationship('User', backref='created_tasks')
    
    def get_device_ids(self):
        return json.loads(self.device_ids) if self.device_ids else []
    
    def set_device_ids(self, ids):
        self.device_ids = json.dumps(ids)

class DeviceLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    result = db.Column(db.Text)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    performed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    device = db.relationship('Device', backref='logs')
    performed_by_user = db.relationship('User', backref='logs')