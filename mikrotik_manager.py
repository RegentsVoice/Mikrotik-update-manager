import paramiko
import re
import logging
from datetime import datetime
import hashlib
import time

logger = logging.getLogger(__name__)


class MikroTikManager:
    # SSH
    
    @staticmethod
    def connect_to_device(device):
        """Открывает SSH-соединение с MikroTik"""
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
        except Exception as e:
            logger.error(f"SSH connection failed ({device.ip_address}): {e}")
            return None

    @staticmethod
    def execute_command(ssh, command, delay=1):
        """Выполняет команду на устройстве"""
        try:
            stdin, stdout, stderr = ssh.exec_command(command)
            time.sleep(delay)
            return {
                'success': True,
                'output': stdout.read().decode('utf-8', errors='ignore'),
                'error': stderr.read().decode('utf-8', errors='ignore')
            }
        except Exception as e:
            return {'success': False, 'output': '', 'error': str(e)}

    # ВСПОМОГАТЕЛЬНЫЕ УТИЛИТЫ

    @staticmethod
    def _safe_close(ssh):
        try:
            ssh.close()
        except Exception:
            pass

    @staticmethod
    def _parse_name_from_file_line(line):
        match = re.search(r'name="([^"]+)"', line)
        return match.group(1) if match else None

    # ИНФОРМАЦИЯ ОБ УСТРОЙСТВЕ

    @staticmethod
    def test_connection(device):
        ssh = MikroTikManager.connect_to_device(device)
        if not ssh:
            return {'status': 'error', 'message': 'Connection failed'}

        result = MikroTikManager.execute_command(ssh, '/system resource print')
        MikroTikManager._safe_close(ssh)

        return (
            {'status': 'success', 'message': 'Connection successful'}
            if result['success']
            else {'status': 'error', 'message': result['error']}
        )

    @staticmethod
    def get_system_info(device):
        ssh = MikroTikManager.connect_to_device(device)
        if not ssh:
            return {'status': 'error', 'message': 'Connection failed'}

        try:
            res = MikroTikManager.execute_command(ssh, '/system resource print')
            identity = MikroTikManager.execute_command(ssh, '/system identity print')

            version = 'Unknown'
            arch = 'Unknown'
            name = 'Unknown'

            if res['success']:
                m = re.search(r'version:\s*(\S+)', res['output'], re.I)
                if m:
                    version = m.group(1)

                a = re.search(r'architecture-name:\s*(\S+)', res['output'], re.I)
                if a:
                    arch = a.group(1)

            if identity['success']:
                n = re.search(r'name:\s*(\S+)', identity['output'], re.I)
                if n:
                    name = n.group(1)

            return {
                'status': 'success',
                'version': version,
                'architecture': arch,
                'identity': name
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
        finally:
            MikroTikManager._safe_close(ssh)

    @staticmethod
    def get_extended_system_info(device):
        """Получение расширенной информации о системе устройства"""
        ssh = MikroTikManager.connect_to_device(device)
        if not ssh:
            return {'status': 'error', 'message': 'Connection failed'}

        try:
            # Базовая информация
            res = MikroTikManager.execute_command(ssh, '/system resource print')
            identity = MikroTikManager.execute_command(ssh, '/system identity print')
            
            # Дополнительная информация
            license = MikroTikManager.execute_command(ssh, '/system license print')
            routerboard = MikroTikManager.execute_command(ssh, '/system routerboard print')
            history = MikroTikManager.execute_command(ssh, '/system history print')
            clock = MikroTikManager.execute_command(ssh, '/system clock print')
            packages = MikroTikManager.execute_command(ssh, '/system package print')
            
            # Сетевая информация
            interfaces = MikroTikManager.execute_command(ssh, '/interface print detail')
            ip_addresses = MikroTikManager.execute_command(ssh, '/ip address print detail')
            
            # RAM информация
            memory = MikroTikManager.execute_command(ssh, '/system resource print')
            
            version = 'Unknown'
            arch = 'Unknown'
            name = 'Unknown'
            board_name = 'Unknown'
            serial_number = 'Unknown'
            firmware_type = 'Unknown'
            license_level = 'Unknown'
            uptime = 'Unknown'
            free_memory = 'Unknown'
            total_memory = 'Unknown'
            cpu_load = 'Unknown'
            cpu_count = 'Unknown'
            cpu_frequency = 'Unknown'
            board_version = 'Unknown'

            # Парсинг основной информации
            if res['success']:
                output = res['output']
                
                # Версия RouterOS
                m = re.search(r'version:\s*(\S+)', output, re.I)
                if m:
                    version = m.group(1)
                
                # Архитектура
                a = re.search(r'architecture-name:\s*(\S+)', output, re.I)
                if a:
                    arch = a.group(1)
                
                # Uptime
                u = re.search(r'uptime:\s*([^\n]+)', output, re.I)
                if u:
                    uptime = u.group(1).strip()
                
                # RAM
                free_match = re.search(r'free-memory:\s*([\d.]+)([KMGT]?B)', output, re.I)
                total_match = re.search(r'total-memory:\s*([\d.]+)([KMGT]?B)', output, re.I)
                
                if free_match:
                    free_memory = f"{free_match.group(1)} {free_match.group(2)}"
                if total_match:
                    total_memory = f"{total_match.group(1)} {total_match.group(2)}"
                
                # CPU
                cpu_match = re.search(r'cpu-load:\s*(\d+)%', output, re.I)
                if cpu_match:
                    cpu_load = f"{cpu_match.group(1)}%"
                
                count_match = re.search(r'cpu-count:\s*(\d+)', output, re.I)
                if count_match:
                    cpu_count = count_match.group(1)
                
                freq_match = re.search(r'cpu-frequency:\s*([\d.]+)\s*MHz', output, re.I)
                if freq_match:
                    cpu_frequency = f"{freq_match.group(1)} MHz"

            if identity['success']:
                n = re.search(r'name:\s*(\S+)', identity['output'], re.I)
                if n:
                    name = n.group(1)

            # Парсинг информации о RouterBoard
            if routerboard['success']:
                rb_output = routerboard['output']
                
                b_match = re.search(r'model:\s*(\S+)', rb_output, re.I)
                if b_match:
                    board_name = b_match.group(1)
                
                s_match = re.search(r'serial-number:\s*(\S+)', rb_output, re.I)
                if s_match:
                    serial_number = s_match.group(1)
                
                fw_match = re.search(r'firmware-type:\s*(\S+)', rb_output, re.I)
                if fw_match:
                    firmware_type = fw_match.group(1)
                
                v_match = re.search(r'current-firmware:\s*(\S+)', rb_output, re.I)
                if v_match:
                    board_version = v_match.group(1)

            # Парсинг лицензии
            if license['success']:
                l_match = re.search(r'software-id:\s*(\S+)', license['output'], re.I)
                if l_match:
                    license_level = l_match.group(1)
            
            # Парсинг времени
            current_time = 'Unknown'
            if clock['success']:
                t_match = re.search(r'time:\s*([^\n]+)', clock['output'], re.I)
                if t_match:
                    current_time = t_match.group(1).strip()
            
            # Сбор информации о пакетах
            package_list = []
            if packages['success']:
                lines = packages['output'].split('\n')
                for line in lines:
                    if 'name=' in line and 'version=' in line:
                        name_match = re.search(r'name=([^ ]+)', line)
                        version_match = re.search(r'version=([^ ]+)', line)
                        if name_match and version_match:
                            package_list.append({
                                'name': name_match.group(1),
                                'version': version_match.group(1)
                            })
            
            # Сбор информации об интерфейсах
            interface_list = []
            if interfaces['success']:
                lines = interfaces['output'].split('\n')
                current_interface = {}
                
                for line in lines:
                    if line.strip() and '=' in line:
                        # Новая запись интерфейса
                        if 'name=' in line and current_interface:
                            interface_list.append(current_interface)
                            current_interface = {}
                        
                        # Парсинг параметров
                        for param in ['name', 'type', 'mtu', 'mac-address', 'running', 'disabled']:
                            pattern = rf'{param}=([^ ]+)'
                            match = re.search(pattern, line)
                            if match:
                                current_interface[param] = match.group(1)
                
                # Добавляем последний интерфейс
                if current_interface:
                    interface_list.append(current_interface)
            
            # Сбор IP адресов
            ip_list = []
            if ip_addresses['success']:
                lines = ip_addresses['output'].split('\n')
                for line in lines:
                    if 'address=' in line and 'interface=' in line:
                        addr_match = re.search(r'address=([^ ]+)', line)
                        iface_match = re.search(r'interface=([^ ]+)', line)
                        network_match = re.search(r'network=([^ ]+)', line)
                        
                        if addr_match and iface_match:
                            ip_info = {
                                'address': addr_match.group(1),
                                'interface': iface_match.group(1)
                            }
                            if network_match:
                                ip_info['network'] = network_match.group(1)
                            ip_list.append(ip_info)
            
            # Получение температуры (если доступно)
            temperature = 'N/A'
            temp_result = MikroTikManager.execute_command(ssh, '/system health print')
            if temp_result['success']:
                temp_match = re.search(r'temperature:\s*([\d.]+)', temp_result['output'], re.I)
                if temp_match:
                    temperature = f"{temp_match.group(1)}°C"
            
            # Получение информации о дисках
            storage_info = 'N/A'
            disk_result = MikroTikManager.execute_command(ssh, '/system resource print')
            if disk_result['success']:
                disk_match = re.search(r'free-hdd-space:\s*([\d.]+)([KMGT]?B)', disk_result['output'], re.I)
                total_disk_match = re.search(r'total-hdd-space:\s*([\d.]+)([KMGT]?B)', disk_result['output'], re.I)
                if disk_match and total_disk_match:
                    storage_info = f"{disk_match.group(1)}{disk_match.group(2)} свободно из {total_disk_match.group(1)}{total_disk_match.group(2)}"
            
            return {
                'status': 'success',
                'basic': {
                    'version': version,
                    'architecture': arch,
                    'identity': name,
                    'uptime': uptime,
                    'current_time': current_time
                },
                'hardware': {
                    'board_name': board_name,
                    'serial_number': serial_number,
                    'firmware_type': firmware_type,
                    'board_version': board_version,
                    'temperature': temperature,
                    'storage': storage_info
                },
                'resources': {
                    'free_memory': free_memory,
                    'total_memory': total_memory,
                    'cpu_load': cpu_load,
                    'cpu_count': cpu_count,
                    'cpu_frequency': cpu_frequency
                },
                'license': {
                    'level': license_level
                },
                'packages': package_list,
                'interfaces': interface_list,
                'ip_addresses': ip_list
            }
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
        finally:
            MikroTikManager._safe_close(ssh)

    # 4. ОБНОВЛЕНИЯ ROUTEROS

    @staticmethod
    def check_for_updates(device):
        ssh = MikroTikManager.connect_to_device(device)
        if not ssh:
            return {'status': 'error', 'message': 'Connection failed'}

        try:
            info = MikroTikManager.get_system_info(device)
            check = MikroTikManager.execute_command(
                ssh,
                '/system package update check-for-updates',
                delay=5
            )

            has_updates = 'new version is available' in check['output'].lower()

            return {
                'status': 'success',
                'current_version': info.get('version'),
                'has_updates': has_updates,
                'raw_output': check['output'][:500]
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
        finally:
            MikroTikManager._safe_close(ssh)

    @staticmethod
    def perform_update(device):
        ssh = MikroTikManager.connect_to_device(device)
        if not ssh:
            return {'status': 'error', 'message': 'Connection failed'}

        try:
            MikroTikManager.execute_command(ssh, '/system package update download', delay=30)
            MikroTikManager.execute_command(ssh, '/system package update install', delay=60)
            return {
                'status': 'success',
                'message': 'Update installed, device rebooting'
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
        finally:
            MikroTikManager._safe_close(ssh)

    @staticmethod
    def perform_update_with_backup(device, create_backup=True):
        """Выполнение обновления с созданием резервной копии"""
        try:
            if create_backup:
                # Создаем резервную копию
                backup_result = MikroTikManager.create_backup(device)
                
            # Выполняем обновление
            return MikroTikManager.perform_update(device)
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    # 5. БЭКАПЫ

    @staticmethod
    def create_backup(device, backup_name=None):
        ssh = MikroTikManager.connect_to_device(device)
        if not ssh:
            return {'status': 'error', 'message': 'Connection failed'}

        try:
            if not backup_name:
                ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                h = hashlib.md5(device.name.encode()).hexdigest()[:4]
                backup_name = f'backup_{h}_{ts}.backup'

            cmd = f'/system backup save name="{backup_name}"'
            res = MikroTikManager.execute_command(ssh, cmd, delay=5)

            return (
                {'status': 'success', 'backup_name': backup_name}
                if res['success']
                else {'status': 'error', 'message': res['error']}
            )
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
        finally:
            MikroTikManager._safe_close(ssh)

    @staticmethod
    def list_backups(device):
        ssh = MikroTikManager.connect_to_device(device)
        if not ssh:
            return {'status': 'error', 'message': 'Connection failed'}

        try:
            res = MikroTikManager.execute_command(
                ssh,
                '/file print detail where type="backup"',
                delay=2
            )

            backups = []
            total_size = 0

            for line in res['output'].splitlines():
                #  имя файла 
                name_match = re.search(r'name=([^ ]+)', line)
                if not name_match:
                    continue

                name = name_match.group(1)

                #  размер
                size = 0
                size_formatted = '—'

                size_match = re.search(r'size=([\d.]+)(B|KiB|MiB)', line)
                if size_match:
                    value = float(size_match.group(1))
                    unit = size_match.group(2)

                    if unit == 'B':
                        size = int(value)
                    elif unit == 'KiB':
                        size = int(value * 1024)
                    elif unit == 'MiB':
                        size = int(value * 1024 * 1024)

                    size_formatted = f'{value} {unit}'
                    total_size += size

                #  дата создания 
                creation_time = 'unknown'
                time_match = re.search(r'last-modified=([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})', line)
                if time_match:
                    creation_time = time_match.group(1)

                backups.append({
                    'name': name,
                    'size': size,
                    'size_formatted': size_formatted,
                    'creation_time': creation_time
                })

            return {
                'status': 'success',
                'count': len(backups),
                'total_size': total_size,
                'backups': backups
            }

        except Exception as e:
            return {'status': 'error', 'message': str(e)}
        finally:
            MikroTikManager._safe_close(ssh)


    @staticmethod
    def delete_backup(device, backup_name):
        ssh = MikroTikManager.connect_to_device(device)
        if not ssh:
            return {'status': 'error', 'message': 'Connection failed'}

        try:
            res = MikroTikManager.execute_command(
                ssh,
                f'/file remove "{backup_name}"',
                delay=2
            )

            return (
                {'status': 'success', 'backup_name': backup_name}
                if res['success']
                else {'status': 'error', 'message': res['error']}
            )
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
        finally:
            MikroTikManager._safe_close(ssh)

    @staticmethod
    def delete_old_backups(device, keep_count=5):
        result = MikroTikManager.list_backups(device)
        if result['status'] != 'success':
            return result

        backups = sorted(result['backups'])
        to_delete = backups[:-keep_count]

        deleted = []
        for name in to_delete:
            r = MikroTikManager.delete_backup(device, name)
            if r['status'] == 'success':
                deleted.append(name)

        return {
            'status': 'success',
            'deleted': deleted,
            'kept': len(backups) - len(deleted)
        }
