import paramiko
import re
import logging
from datetime import datetime
import hashlib

# Настройка логирования
logger = logging.getLogger(__name__)

class MikroTikManager:
    @staticmethod
    def connect_to_device(device):
        """Подключение к устройству MikroTik"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                hostname=device.ip_address,
                port=device.port,
                username=device.username,
                password=device.password,
                timeout=10,
                banner_timeout=15,
                auth_timeout=10
            )
            
            return ssh
        except paramiko.AuthenticationException as e:
            logger.error(f"Authentication failed for {device.ip_address}: {str(e)}")
            return None
        except paramiko.SSHException as e:
            logger.error(f"SSH error for {device.ip_address}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Connection error to {device.ip_address}: {str(e)}")
            return None
    
    @staticmethod
    def execute_command(ssh, command, delay=1):
        """Выполнение команды на MikroTik"""
        try:
            stdin, stdout, stderr = ssh.exec_command(command)
            
            # Ждем выполнения команды
            import time
            time.sleep(delay)
            
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            
            return {
                'success': True,
                'output': output,
                'error': error
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'output': ''
            }
    
    @staticmethod
    def get_system_info(device):
        """Получение информации о системе"""
        ssh = MikroTikManager.connect_to_device(device)
        if not ssh:
            return {'status': 'error', 'message': 'Connection failed'}
        
        try:
            # Получаем версию RouterOS
            result = MikroTikManager.execute_command(ssh, '/system resource print')
            output = result['output']
            
            # Парсим версию разными способами
            version = None
            
            # Способ 1: Ищем в строке version:
            version_match = re.search(r'version:\s*(\S+)', output, re.IGNORECASE)
            if version_match:
                version = version_match.group(1).strip()
            else:
                # Способ 2: Ищем RouterOS X.X.X
                ros_match = re.search(r'RouterOS\s+(\d+\.\d+(?:\.\d+)?)', output, re.IGNORECASE)
                if ros_match:
                    version = ros_match.group(1)
                else:
                    # Способ 3: Ищем любую версию в формате X.X.X
                    any_version = re.search(r'(\d+\.\d+(?:\.\d+)?)\s*\(stable\)', output)
                    if any_version:
                        version = any_version.group(1)
            
            # Получаем архитектуру
            arch = 'unknown'
            arch_match = re.search(r'architecture-name:\s*(\S+)', output, re.IGNORECASE)
            if arch_match:
                arch = arch_match.group(1).strip()
            
            # Получаем имя устройства
            identity_result = MikroTikManager.execute_command(ssh, '/system identity print')
            identity = 'unknown'
            if identity_result['success']:
                name_match = re.search(r'name:\s*(\S+)', identity_result['output'], re.IGNORECASE)
                if name_match:
                    identity = name_match.group(1).strip()
            
            ssh.close()
            
            return {
                'status': 'success',
                'version': version or 'Unknown',
                'architecture': arch,
                'identity': identity,
                'raw_output': output[:500]  # Ограничиваем для логов
            }
            
        except Exception as e:
            ssh.close()
            return {'status': 'error', 'message': str(e)}
    
    @staticmethod
    def check_for_updates(device):
        """Проверка наличия обновлений"""
        ssh = MikroTikManager.connect_to_device(device)
        if not ssh:
            return {'status': 'error', 'message': 'Connection failed'}
        
        try:
            # Получаем текущую версию
            system_info = MikroTikManager.get_system_info(device)
            if system_info['status'] != 'success':
                ssh.close()
                return system_info
            
            # Проверяем обновления
            check_result = MikroTikManager.execute_command(ssh, '/system package update check-for-updates', delay=5)
            check_output = check_result['output']
            
            # Получаем информацию о текущих пакетах
            packages_result = MikroTikManager.execute_command(ssh, '/system package update print')
            packages_output = packages_result['output']
            
            ssh.close()
            
            # Анализируем результат
            has_updates = False
            update_status = 'unknown'
            
            # Проверяем наличие сообщений об обновлениях
            if 'status: new version is available' in check_output.lower():
                has_updates = True
                update_status = 'available'
            elif 'already have latest' in check_output.lower():
                has_updates = False
                update_status = 'latest'
            elif 'checking for updates' in check_output.lower():
                update_status = 'checking'
            
            return {
                'status': 'success',
                'current_version': system_info['version'],
                'has_updates': has_updates,
                'update_status': update_status,
                'check_output': check_output[:500],
                'packages_info': packages_output[:500],
                'device_name': system_info['identity']
            }
            
        except Exception as e:
            ssh.close()
            return {'status': 'error', 'message': str(e)}
    
    @staticmethod
    def perform_update(device):
        """Выполнение обновления MikroTik"""
        ssh = MikroTikManager.connect_to_device(device)
        if not ssh:
            return {'status': 'error', 'message': 'Connection failed'}
        
        try:
            # Скачиваем обновления
            download_result = MikroTikManager.execute_command(ssh, '/system package update download', delay=30)
            
            # Даем дополнительное время на скачивание
            import time
            time.sleep(10)
            
            # Проверяем статус скачивания
            status_result = MikroTikManager.execute_command(ssh, '/system package update print')
            
            # Устанавливаем обновления
            install_result = MikroTikManager.execute_command(ssh, '/system package update install', delay=60)
            
            ssh.close()
            
            return {
                'status': 'success',
                'download_output': download_result['output'][:500],
                'status_output': status_result['output'][:500],
                'install_output': install_result['output'][:500],
                'message': 'Update process completed. Device will reboot.'
            }
            
        except Exception as e:
            ssh.close()
            return {'status': 'error', 'message': str(e)}
    
    @staticmethod
    def test_connection(device):
        """Тест подключения к устройству"""
        ssh = MikroTikManager.connect_to_device(device)
        if not ssh:
            return {'status': 'error', 'message': 'Connection failed'}
        
        try:
            # Выполняем простую команду для проверки
            result = MikroTikManager.execute_command(ssh, '/system resource print')
            
            ssh.close()
            
            if result['success']:
                return {'status': 'success', 'message': 'Connection successful'}
            else:
                return {'status': 'error', 'message': result['error']}
                
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    @staticmethod
    def create_backup(device, backup_name=None):
        """Создание резервной копии конфигурации"""
        ssh = MikroTikManager.connect_to_device(device)
        if not ssh:
            return {'status': 'error', 'message': 'Connection failed'}
        
        try:
            # Генерируем имя для бэкапа (максимум 8 символов)
            if not backup_name:
                # Создаем короткий хэш из имени устройства и времени
                timestamp = datetime.now().strftime("%H%M%S")
                device_hash = hashlib.md5(device.name.encode()).hexdigest()[:3]
                backup_name = f"b{device_hash}{timestamp[:4]}"
                
                # Обрезаем до 8 символов если нужно
                backup_name = backup_name[:8]
            
            # Убедимся, что имя не длиннее 8 символов
            backup_name = backup_name[:8]
            
            # Создаем бэкап
            backup_command = f'/system backup save name="{backup_name}"'
            result = MikroTikManager.execute_command(ssh, backup_command, delay=3)
            
            ssh.close()
            
            if result['success']:
                return {
                    'status': 'success',
                    'message': f'Backup created: {backup_name}',
                    'backup_name': backup_name,
                    'output': result['output']
                }
            else:
                return {'status': 'error', 'message': result['error']}
                
        except Exception as e:
            ssh.close()
            return {'status': 'error', 'message': str(e)}
    
    @staticmethod
    def list_backups(device):
        """Получение списка резервных копий - простой подход"""
        ssh = MikroTikManager.connect_to_device(device)
        if not ssh:
            return {'status': 'error', 'message': 'Connection failed'}
        
        try:
            # Пробуем несколько команд для получения списка бэкапов
            backups = []
            
            # Команда 1: используем find для поиска файлов .backup
            result = MikroTikManager.execute_command(ssh, 
                '/file find where name~".backup"', 
                delay=2)
            
            if result['success'] and result['output'].strip():
                file_ids = result['output'].strip().split('\n')
                
                for file_id in file_ids:
                    if file_id.strip():
                        # Получаем информацию о каждом файле
                        info_cmd = f'/file print detail where number={file_id.strip()}'
                        info_result = MikroTikManager.execute_command(ssh, info_cmd, delay=1)
                        
                        if info_result['success']:
                            output = info_result['output']
                            # Парсим вывод
                            name = 'unknown'
                            size = 0
                            date = 'unknown'
                            
                            # Ищем имя
                            name_match = re.search(r'name="([^"]+)"', output)
                            if name_match:
                                name = name_match.group(1)
                            
                            # Ищем размер
                            size_match = re.search(r'size=(\d+)', output)
                            if size_match:
                                try:
                                    size = int(size_match.group(1))
                                except:
                                    size = 0
                            
                            # Ищем дату создания
                            date_match = re.search(r'creation-time=([a-z]+/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2})', output, re.IGNORECASE)
                            if date_match:
                                date = date_match.group(1)
                            
                            # Форматируем размер
                            if size >= 1024*1024:
                                size_formatted = f"{size/(1024*1024):.1f} MB"
                            elif size >= 1024:
                                size_formatted = f"{size/1024:.1f} KB"
                            else:
                                size_formatted = f"{size} bytes"
                            
                            backups.append({
                                'name': name,
                                'size': size,
                                'date': date,
                                'size_formatted': size_formatted,
                                'creation_time': date
                            })
            
            # Если не нашли через find, пробуем другой подход
            if not backups:
                result2 = MikroTikManager.execute_command(ssh, 
                    '/file print detail without-paging where type="backup"', 
                    delay=2)
                
                if result2['success']:
                    lines = result2['output'].split('\n')
                    current_backup = {}
                    
                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue
                        
                        # Если строка начинается с цифры (номер файла)
                        if re.match(r'^\d+', line):
                            # Если у нас уже есть собранный бэкап, сохраняем его
                            if current_backup and 'name' in current_backup:
                                # Форматируем размер
                                size = current_backup.get('size', 0)
                                if isinstance(size, int):
                                    if size >= 1024*1024:
                                        current_backup['size_formatted'] = f"{size/(1024*1024):.1f} MB"
                                    elif size >= 1024:
                                        current_backup['size_formatted'] = f"{size/1024:.1f} KB"
                                    else:
                                        current_backup['size_formatted'] = f"{size} bytes"
                                else:
                                    current_backup['size_formatted'] = '0 bytes'
                                
                                backups.append(current_backup.copy())
                            
                            # Начинаем новый бэкап
                            current_backup = {'name': '', 'size': 0, 'date': 'unknown'}
                        
                        # Ищем параметры
                        if 'name=' in line:
                            name_match = re.search(r'name="([^"]+)"', line)
                            if name_match:
                                current_backup['name'] = name_match.group(1)
                        
                        if 'size=' in line:
                            size_match = re.search(r'size=(\d+)', line)
                            if size_match:
                                try:
                                    current_backup['size'] = int(size_match.group(1))
                                except:
                                    current_backup['size'] = 0
                        
                        if 'creation-time=' in line:
                            date_match = re.search(r'creation-time=([a-z]+/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2})', line, re.IGNORECASE)
                            if date_match:
                                current_backup['date'] = date_match.group(1)
                                current_backup['creation_time'] = date_match.group(1)
                    
                    # Добавляем последний бэкап
                    if current_backup and 'name' in current_backup:
                        # Форматируем размер
                        size = current_backup.get('size', 0)
                        if isinstance(size, int):
                            if size >= 1024*1024:
                                current_backup['size_formatted'] = f"{size/(1024*1024):.1f} MB"
                            elif size >= 1024:
                                current_backup['size_formatted'] = f"{size/1024:.1f} KB"
                            else:
                                current_backup['size_formatted'] = f"{size} bytes"
                        else:
                            current_backup['size_formatted'] = '0 bytes'
                        
                        backups.append(current_backup)
            
            ssh.close()
            
            # Фильтруем только файлы .backup
            filtered_backups = []
            for backup in backups:
                if backup['name'].endswith('.backup'):
                    filtered_backups.append(backup)
            
            return {
                'status': 'success',
                'backups': filtered_backups,
                'count': len(filtered_backups),
                'raw_output': ''
            }
                
        except Exception as e:
            try:
                ssh.close()
            except:
                pass
            return {'status': 'error', 'message': str(e)}
    
    @staticmethod
    def restore_backup(device, backup_name):
        """Восстановление из резервной копии"""
        ssh = MikroTikManager.connect_to_device(device)
        if not ssh:
            return {'status': 'error', 'message': 'Connection failed'}
        
        try:
            # Восстанавливаем бэкап
            restore_command = f'/system backup load name="{backup_name}"'
            result = MikroTikManager.execute_command(ssh, restore_command, delay=5)
            
            ssh.close()
            
            if result['success']:
                return {
                    'status': 'success',
                    'message': f'Backup restored: {backup_name}',
                    'output': result['output']
                }
            else:
                return {'status': 'error', 'message': result['error']}
                
        except Exception as e:
            ssh.close()
            return {'status': 'error', 'message': str(e)}
    
    @staticmethod
    def delete_backup(device, backup_name):
        """Удаление резервной копии"""
        ssh = MikroTikManager.connect_to_device(device)
        if not ssh:
            return {'status': 'error', 'message': 'Connection failed'}
        
        try:
            # Удаляем бэкап
            delete_command = f'/file remove "{backup_name}"'
            result = MikroTikManager.execute_command(ssh, delete_command, delay=2)
            
            ssh.close()
            
            if result['success']:
                return {
                    'status': 'success',
                    'message': f'Backup deleted: {backup_name}',
                    'output': result['output']
                }
            else:
                return {'status': 'error', 'message': result['error']}
                
        except Exception as e:
            ssh.close()
            return {'status': 'error', 'message': str(e)}
    
    @staticmethod
    def delete_old_backups(device, keep_count=5):
        """Удаление старых бэкапов, оставляя только keep_count последних"""
        ssh = MikroTikManager.connect_to_device(device)
        if not ssh:
            return {'status': 'error', 'message': 'Connection failed'}
        
        try:
            # Получаем список бэкапов
            list_result = MikroTikManager.execute_command(ssh, '/file print where type="backup"', delay=2)
            
            if not list_result['success']:
                ssh.close()
                return {'status': 'error', 'message': list_result['error']}
            
            # Парсим и сортируем бэкапы
            backups = []
            lines = list_result['output'].split('\n')
            
            for line in lines:
                if '.backup' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        backup_name = ''
                        for part in parts:
                            if part.startswith('name='):
                                backup_name = part.split('=')[1].strip('"')
                                break
                        
                        if backup_name:
                            # Пытаемся извлечь дату из имени
                            try:
                                # Для коротких имен используем текущее время
                                date_str = backup_name.replace('.backup', '')
                                if len(date_str) == 8 and date_str[0] == 'b':
                                    # Извлекаем время из хэша (последние 4 символа)
                                    time_str = date_str[4:]  # bABC1234 -> 1234
                                    if time_str.isdigit():
                                        # Создаем дату с сегодняшним числом
                                        today = datetime.now().strftime("%Y%m%d")
                                        date = datetime.strptime(f"{today}_{time_str}", "%Y%m%d_%H%M")
                                        backups.append((date, backup_name))
                                    else:
                                        backups.append((datetime.now(), backup_name))
                                else:
                                    # Старый формат с датой
                                    date_str = backup_name.split('_')[-1].replace('.backup', '')
                                    date = datetime.strptime(date_str, "%Y%m%d_%H%M%S")
                                    backups.append((date, backup_name))
                            except:
                                # Если не удалось распарсить дату, добавляем в конец
                                backups.append((datetime.min, backup_name))
            
            # Сортируем по дате (сначала старые)
            backups.sort(key=lambda x: x[0])
            
            # Удаляем старые бэкапы
            deleted = []
            if len(backups) > keep_count:
                to_delete = backups[:-keep_count]  # Все кроме последних keep_count
                
                for _, backup_name in to_delete:
                    delete_result = MikroTikManager.execute_command(ssh, f'/file remove "{backup_name}"', delay=1)
                    if delete_result['success']:
                        deleted.append(backup_name)
            
            ssh.close()
            
            return {
                'status': 'success',
                'message': f'Deleted {len(deleted)} old backups',
                'deleted': deleted,
                'kept': len(backups) - len(deleted)
            }
                
        except Exception as e:
            ssh.close()
            return {'status': 'error', 'message': str(e)}
    
    @staticmethod
    def perform_update_with_backup(device, create_backup=True):
        """Выполнение обновления с возможностью создания бэкапа"""
        if create_backup:
            # Создаем бэкап перед обновлением с коротким именем
            import hashlib
            import time
            
            # Создаем уникальное короткое имя
            timestamp = datetime.now().strftime("%H%M%S")
            device_hash = hashlib.md5(device.name.encode()).hexdigest()[:3]
            backup_name = f"b{device_hash}{timestamp[:4]}"  # Формат: bABC1234
            
            # Обрезаем до 8 символов
            backup_name = backup_name[:8]
            
            backup_result = MikroTikManager.create_backup(device, backup_name)
            
            if backup_result['status'] != 'success':
                # Если не удалось создать бэкап, можно продолжить или остановиться
                # Здесь продолжаем, но логируем ошибку
                logger.warning(f"Failed to create backup for {device.name}: {backup_result['message']}")
        
        # Выполняем обновление
        update_result = MikroTikManager.perform_update(device)
        
        # Удаляем старые бэкапы (оставляем 5 последних)
        if create_backup:
            cleanup_result = MikroTikManager.delete_old_backups(device, keep_count=5)
            logger.info(f"Backup cleanup for {device.name}: {cleanup_result.get('message', '')}")
        
        return update_result
    
    # Алиасы для обратной совместимости
    @staticmethod
    def check_updates(device):
        """Алиас для check_for_updates (обратная совместимость)"""
        return MikroTikManager.check_for_updates(device)