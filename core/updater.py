import time
import re
import logging
from typing import Dict, Any, List
from .connector import MikroTikSSHConnector
from .backup_manager import BackupManager

class MikroTikUpdater:
    def __init__(self, connector: MikroTikSSHConnector):
        self.connector = connector
        self.backup_manager = BackupManager(connector)
        self.logger = logging.getLogger('mikrotik_manager')
        
        if not self.logger.handlers:
            self.logger.addHandler(logging.NullHandler())
            self.logger.propagate = False
    
    def _compare_versions(self, current: str, latest: str) -> bool:
        try:
            current_clean = current.split()[0]
            latest_clean = latest.split()[0]
            
            current_parts = list(map(int, current_clean.split('.')))
            latest_parts = list(map(int, latest_clean.split('.')))
            
            for i in range(max(len(current_parts), len(latest_parts))):
                current_val = current_parts[i] if i < len(current_parts) else 0
                latest_val = latest_parts[i] if i < len(latest_parts) else 0
                
                if latest_val > current_val:
                    return True
                elif latest_val < current_val:
                    return False
            
            return False
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка сравнения версий {current} vs {latest}: {str(e)}")
            return False
    
    def get_current_version(self, device_name: str) -> str:
        try:
            info = self.connector.get_routeros_info(device_name)
            version = info.get('version', 'Неизвестно')
            self.logger.info(f"📋 Текущая версия {device_name}: {version}")
            return version
        except Exception as e:
            self.logger.error(f"❌ Ошибка получения версии для {device_name}: {str(e)}")
            return "Ошибка"
    
    def check_for_updates(self, device_name: str) -> Dict[str, Any]:
        try:
            self.logger.info(f"🔍 Проверка обновлений для {device_name}")
            
            current_version = self.get_current_version(device_name)
            if current_version == "Ошибка":
                return {
                    'available': False,
                    'current_version': 'Ошибка',
                    'latest_version': 'Ошибка',
                    'status': 'Ошибка получения текущей версии'
                }
            
            self.connector.execute_command(device_name, '/system package update check-for-updates once')
            
            self.logger.info("⏳ Ожидание завершения проверки обновлений...")
            time.sleep(5)
            
            output, error = self.connector.execute_command(device_name, '/system package update print')
            
            update_info = self._parse_update_status(output)
            latest_version = update_info.get('latest_version', 'Неизвестно')
            
            update_available = False
            if latest_version != 'Неизвестно' and current_version != 'Неизвестно':
                update_available = self._compare_versions(current_version, latest_version)
            
            result = {
                'available': update_available,
                'current_version': current_version,
                'latest_version': latest_version,
                'status': update_info.get('status', 'Проверка завершена')
            }
            
            self.logger.info(f"📊 Результат проверки обновлений {device_name}: доступно={update_available}")
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка проверки обновлений для {device_name}: {str(e)}")
            return {
                'available': False,
                'current_version': 'Ошибка',
                'latest_version': 'Ошибка',
                'status': f'Ошибка: {str(e)}'
            }
    
    def _parse_update_status(self, output: List[str]) -> Dict[str, Any]:
        status_info = {
            'available': False,
            'status': 'Неизвестно',
            'latest_version': 'Неизвестно',
            'current_version': 'Неизвестно'
        }
        
        for line in output:
            line_lower = line.lower()
            if 'status:' in line_lower:
                status_info['status'] = line.split(':', 1)[1].strip()
                if 'update available' in line_lower:
                    status_info['available'] = True
            elif 'latest-version:' in line_lower:
                status_info['latest_version'] = line.split(':', 1)[1].strip()
            elif 'installed-version:' in line_lower:
                status_info['current_version'] = line.split(':', 1)[1].strip()
        
        return status_info
    
    def install_update(self, device_name: str) -> Dict[str, Any]:
        try:
            self.logger.info(f"🚀 Начало установки обновления для {device_name}")
            
            self.logger.info("💾 Создание бэкапа перед обновлением...")
            backup_success, backup_name = self.backup_manager.create_backup(device_name, "before_update")
            
            if not backup_success:
                self.logger.error("❌ Не удалось создать бэкап перед обновлением")
                return {
                    'success': False, 
                    'message': 'Не удалось создать бэкап перед обновлением',
                    'backup_file': ''
                }
            
            self.logger.info(f"✅ Бэкап создан: {backup_name}")
            
            self.logger.info("📥 Скачивание обновления...")
            output, error = self.connector.execute_command(device_name, '/system package update download')
            
            if error and any('error' in err.lower() for err in error if err.strip()):
                self.logger.error(f"❌ Ошибка скачивания обновления: {error}")
                return {
                    'success': False, 
                    'message': f'Ошибка скачивания: {error}',
                    'backup_file': backup_name
                }
            
            self.logger.info("⏳ Ожидание завершения загрузки...")
            download_complete = False
            
            for i in range(30):
                time.sleep(10)
                status_output, _ = self.connector.execute_command(device_name, '/system package update print')
                
                status_text = '\n'.join(status_output)
                self.logger.info(f"📊 Статус загрузки (попытка {i+1}/30): {status_text}")
                
                if any('status: downloaded' in line.lower() for line in status_output):
                    download_complete = True
                    self.logger.info("✅ Загрузка обновления завершена")
                    break
                elif any('error' in line.lower() for line in status_output):
                    error_msg = f"Ошибка загрузки: {status_output}"
                    self.logger.error(f"❌ {error_msg}")
                    return {
                        'success': False, 
                        'message': error_msg,
                        'backup_file': backup_name
                    }
            
            if not download_complete:
                self.logger.error("❌ Таймаут загрузки обновления")
                return {
                    'success': False, 
                    'message': 'Таймаут загрузки обновления',
                    'backup_file': backup_name
                }
            
            self.logger.info("⚡ Установка обновления...")
            output, error = self.connector.execute_command(device_name, '/system package update install')
            
            if error and any('error' in err.lower() for err in error if err.strip()):
                self.logger.error(f"❌ Ошибка установки обновления: {error}")
                return {
                    'success': False, 
                    'message': f'Ошибка установки: {error}',
                    'backup_file': backup_name
                }
            
            self.logger.info(f"✅ Обновление установлено для {device_name}")
            return {
                'success': True, 
                'message': 'Обновление успешно установлено',
                'backup_file': backup_name
            }
            
        except Exception as e:
            self.logger.error(f"❌ Критическая ошибка установки обновления для {device_name}: {str(e)}")
            return {
                'success': False, 
                'message': f'Критическая ошибка установки: {str(e)}',
                'backup_file': backup_name if 'backup_name' in locals() else ''
            }
    
    def check_all_devices(self) -> Dict[str, Any]:
        results = {}
        
        for device_name in self.connector.devices.keys():
            self.logger.info(f"🔍 Проверка устройства: {device_name}")
            
            if not self.connector.test_connection(device_name):
                results[device_name] = {
                    'status': 'offline',
                    'current_version': 'Недоступно',
                    'update_available': False,
                    'message': 'Устройство недоступно'
                }
                self.logger.warning(f"⚠️ Устройство {device_name} недоступно")
                continue
            
            update_info = self.check_for_updates(device_name)
            
            results[device_name] = {
                'status': 'online',
                'current_version': update_info.get('current_version', 'Неизвестно'),
                'latest_version': update_info.get('latest_version', 'Неизвестно'),
                'update_available': update_info.get('available', False),
                'message': update_info.get('status', 'Проверка завершена')
            }
            
            status = "доступно" if update_info.get('available') else "не требуется"
            self.logger.info(f"📊 Результат для {device_name}: обновление {status}")
        
        return results
