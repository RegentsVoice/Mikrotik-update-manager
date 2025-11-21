import schedule
import time
import threading
import yaml
import logging
from datetime import datetime
from typing import Dict, Any, List
from .connector import MikroTikSSHConnector
from .updater import MikroTikUpdater
from .reporter import ReportManager
from .backup_manager import BackupManager

class TaskScheduler:
    def __init__(self, connector: MikroTikSSHConnector, updater: MikroTikUpdater, reporter: ReportManager):
        self.connector = connector
        self.updater = updater
        self.reporter = reporter
        self.backup_manager = BackupManager(connector)
        self.scheduler_config = self._load_scheduler_config()
        self.is_running = False
        self.scheduler_thread = None
        
        self._setup_logging()
    
    def _setup_logging(self):
        self.logger = logging.getLogger('mikrotik_scheduler')
        
        notifications_config = self.scheduler_config.get('notifications', {})
        log_to_file = notifications_config.get('log_to_file', True)
        console_logging = notifications_config.get('console_logging', True)
        
        if not log_to_file and not console_logging:
            self.logger.handlers = []
            self.logger.addHandler(logging.NullHandler())
            self.logger.propagate = False
            return
        
        self.logger.setLevel(logging.INFO)
        
        if log_to_file:
            import os
            if not os.path.exists('logs'):
                os.makedirs('logs')
            
            file_handler = logging.FileHandler('logs/scheduler.log', encoding='utf-8')
            file_handler.setLevel(logging.INFO)
            
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(formatter)
            
            if not any(isinstance(h, logging.FileHandler) for h in self.logger.handlers):
                self.logger.addHandler(file_handler)
        
        if console_logging:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(formatter)
            
            if not any(isinstance(h, logging.StreamHandler) for h in self.logger.handlers):
                self.logger.addHandler(console_handler)
    
    def _load_scheduler_config(self) -> Dict[str, Any]:
        try:
            with open('config/scheduler.yaml', 'r', encoding='utf-8') as file:
                return yaml.safe_load(file)
        except Exception as e:
            print(f"❌ Ошибка загрузки конфигурации планировщика: {e}")
            return {}
    
    def _should_run_today(self, days: List[str]) -> bool:
        if not days:
            return True
        
        today = datetime.now().strftime("%A").lower()
        return today in [day.lower() for day in days]
    
    def _get_devices_for_task(self, task_config: Dict[str, Any]) -> List[str]:
        devices = task_config.get('devices', [])
        if not devices or devices == ['all']:
            return list(self.connector.devices.keys())
        return [d for d in devices if d in self.connector.devices]

    def task_version_check(self, show_progress: bool = True):
        config = self.scheduler_config.get('scheduler', {}).get('version_check', {})
        
        if not config.get('enabled', False):
            return
        
        if not self._should_run_today(config.get('days', [])):
            return
        
        self.logger.info("🔄 Запуск автоматической проверки версий")
        if show_progress:
            print("🔄 Запуск проверки версий на всех устройствах...")
        
        try:
            results = {}
            devices = self._get_devices_for_task(config)
            total_devices = len(devices)
            
            for index, device_name in enumerate(devices, 1):
                if show_progress:
                    print(f"🔍 [{index}/{total_devices}] Проверка {device_name}...")
                
                if not self.connector.test_connection(device_name):
                    results[device_name] = {
                        'status': 'offline',
                        'message': 'Устройство недоступно'
                    }
                    if show_progress:
                        print(f"   ❌ Устройство недоступно")
                    continue
                
                device_info = self.connector.get_routeros_info(device_name)
                
                if 'error' in device_info:
                    results[device_name] = {
                        'status': 'error',
                        'message': device_info['error']
                    }
                    if show_progress:
                        print(f"   ❌ Ошибка: {device_info['error']}")
                else:
                    results[device_name] = {
                        'status': 'online',
                        'current_version': device_info.get('version', 'Неизвестно'),
                        'identity': device_info.get('identity', 'Неизвестно'),
                        'model': device_info.get('model', 'Неизвестно')
                    }
                    if show_progress:
                        version = device_info.get('version', 'Неизвестно')
                        print(f"   ✅ Версия: {version}")
            
            online_count = sum(1 for info in results.values() if info.get('status') == 'online')
            self.logger.info(f"✅ Проверка версий завершена. Онлайн: {online_count}/{len(results)}")
            
            if show_progress:
                print(f"\nПРОВЕРКА ВЕРСИЙ ЗАВЕРШЕНА:")
                print(f"   ✅ Онлайн: {online_count} устройств")
                print(f"   ❌ Оффлайн: {len(results) - online_count} устройств")
                print(f"   📦 Всего проверено: {len(results)} устройств")
            
            if config.get('telegram_report', False):
                report = self.reporter.create_version_report(results)
                if self.reporter.send_telegram_message(report):
                    self.logger.info("📤 Отчет о версиях отправлен в Telegram")
                    if show_progress:
                        print("   📤 Отчет отправлен в Telegram")
                else:
                    self.logger.error("❌ Ошибка отправки отчета в Telegram")
                    if show_progress:
                        print("   ❌ Ошибка отправки отчета в Telegram")
            
        except Exception as e:
            error_msg = f"❌ Ошибка при проверке версий: {str(e)}"
            self.logger.error(error_msg)
            if show_progress:
                print(error_msg)

    def task_update_check(self, show_progress: bool = True):
        config = self.scheduler_config.get('scheduler', {}).get('update_check', {})
        
        if not config.get('enabled', False):
            return
        
        if not self._should_run_today(config.get('days', [])):
            return
        
        self.logger.info("🔄 Запуск автоматической проверки обновлений")
        if show_progress:
            print("🔄 Запуск автоматической проверки обновлений...")
        
        try:
            results = self.updater.check_all_devices()
            
            updates_available = sum(1 for info in results.values() if info.get('update_available'))
            online_count = sum(1 for info in results.values() if info.get('status') == 'online')
            
            self.logger.info(f"✅ Проверка обновлений завершена. Доступно обновлений: {updates_available}")
            
            if show_progress:
                print(f"\n📊 ПРОВЕРКА ОБНОВЛЕНИЙ ЗАВЕРШЕНА:")
                print(f"   ✅ Онлайн: {online_count} устройств")
                print(f"   🔄 Доступно обновлений: {updates_available} устройств")
                print(f"   📦 Всего проверено: {len(results)} устройств")
            
            if config.get('telegram_report', False):
                report = self.reporter.create_update_report(results)
                if self.reporter.send_telegram_message(report):
                    self.logger.info("📤 Отчет об обновлениях отправлен в Telegram")
                    if show_progress:
                        print("   📤 Отчет отправлен в Telegram")
                else:
                    self.logger.error("❌ Ошибка отправки отчета в Telegram")
                    if show_progress:
                        print("   ❌ Ошибка отправки отчета в Telegram")
            
        except Exception as e:
            error_msg = f"❌ Ошибка при проверке обновлений: {str(e)}"
            self.logger.error(error_msg)
            if show_progress:
                print(error_msg)

    def task_auto_update(self, show_progress: bool = True):
        """Задача автоматического обновления"""
        config = self.scheduler_config.get('scheduler', {}).get('auto_update', {})
        
        if not config.get('enabled', False):
            return
        
        if not self._should_run_today(config.get('days', [])):
            return
        
        self.logger.info("🔄 Запуск автоматического обновления")
        if show_progress:
            print("🔄 Запуск автоматического обновления...")
        
        results = {}
        devices = self._get_devices_for_task(config)
        total_devices = len(devices)
        
        for index, device_name in enumerate(devices, 1):
            if show_progress:
                print(f"🔧 [{index}/{total_devices}] Обновление устройства {device_name}...")
            
            self.logger.info(f"🔧 Обновление устройства {device_name}")
            
            try:
                backup_success, backup_name = self.backup_manager.create_backup(device_name, "auto_update")
                if not backup_success:
                    results[device_name] = {
                        'status': 'backup_failed',
                        'message': 'Не удалось создать бэкап'
                    }
                    if show_progress:
                        print(f"   ❌ Не удалось создать бэкап")
                    continue
                
                update_info = self.updater.check_for_updates(device_name)
                
                if not update_info.get('available'):
                    results[device_name] = {
                        'status': 'no_update',
                        'message': 'Обновления не требуются',
                        'backup_file': backup_name
                    }
                    self.logger.info(f"✅ {device_name}: обновления не требуются")
                    if show_progress:
                        print(f"   ✅ Обновления не требуются")
                    continue
                
                result = self.updater.install_update(device_name)
                
                if result['success']:
                    results[device_name] = {
                        'status': 'updated',
                        'message': f"Успешно обновлено до {update_info['latest_version']}",
                        'new_version': update_info['latest_version'],
                        'backup_file': backup_name
                    }
                    self.logger.info(f"✅ {device_name}: успешно обновлено. Бэкап: {backup_name}")
                    if show_progress:
                        print(f"   ✅ Успешно обновлено до {update_info['latest_version']}")
                else:
                    results[device_name] = {
                        'status': 'failed',
                        'message': result['message'],
                        'backup_file': backup_name
                    }
                    self.logger.error(f"❌ {device_name}: ошибка обновления - {result['message']}")
                    if show_progress:
                        print(f"   ❌ Ошибка обновления: {result['message']}")
                
            except Exception as e:
                results[device_name] = {
                    'status': 'error',
                    'message': str(e)
                }
                self.logger.error(f"❌ {device_name}: ошибка - {str(e)}")
                if show_progress:
                    print(f"   ❌ Ошибка: {str(e)}")
        
        if show_progress:
            updated_count = sum(1 for r in results.values() if r.get('status') == 'updated')
            failed_count = sum(1 for r in results.values() if r.get('status') in ['failed', 'error', 'backup_failed'])
            no_update_count = sum(1 for r in results.values() if r.get('status') == 'no_update')
            
            print(f"\n📊 ИТОГИ АВТОМАТИЧЕСКОГО ОБНОВЛЕНИЯ:")
            print(f"   ✅ Обновлено: {updated_count} устройств")
            print(f"   ⏭️  Без обновлений: {no_update_count} устройств")
            print(f"   ❌ Ошибок: {failed_count} устройств")
            print(f"   📦 Всего обработано: {len(results)} устройств")
        
        if config.get('telegram_report', False):
            self._send_auto_update_report(results)

    def _send_auto_update_report(self, results: Dict[str, Any]):
        """Отправка детального отчета об автоматическом обновлении"""
        report = self.reporter.create_auto_update_report(results)
        
        if self.reporter.send_telegram_message(report):
            self.logger.info("📤 Отчет об автоматическом обновлении отправлен в Telegram")
        else:
            self.logger.error("❌ Ошибка отправки отчета об обновлении в Telegram")

    def task_create_backups(self, show_progress: bool = True):
        """Задача создания бэкапов на всех устройствах"""
        config = self.scheduler_config.get('scheduler', {}).get('auto_backup', {})
        
        if not config.get('enabled', False):
            return
        
        if not self._should_run_today(config.get('days', [])):
            return
        
        self.logger.info("💾 Запуск автоматического создания бэкапов")
        if show_progress:
            print("💾 Запуск создания бэкапов на всех устройствах...")
        
        results = {}
        devices = self._get_devices_for_task(config)
        total_devices = len(devices)
        
        for index, device_name in enumerate(devices, 1):
            if show_progress:
                print(f"📦 [{index}/{total_devices}] Создание бэкапа для {device_name}...")
            
            self.logger.info(f"💾 Создание бэкапа для {device_name}")
            
            try:
                success, backup_name = self.backup_manager.create_backup(device_name, "scheduled")
                
                if success:
                    results[device_name] = {
                        'status': 'success',
                        'backup_file': backup_name,
                        'message': 'Бэкап успешно создан'
                    }
                    self.logger.info(f"✅ {device_name}: бэкап создан - {backup_name}")
                    if show_progress:
                        print(f"   ✅ Успешно: {backup_name}")
                else:
                    results[device_name] = {
                        'status': 'failed',
                        'message': 'Ошибка создания бэкапа'
                    }
                    self.logger.error(f"❌ {device_name}: ошибка создания бэкапа")
                    if show_progress:
                        print(f"   ❌ Ошибка создания бэкапа")
                
            except Exception as e:
                results[device_name] = {
                    'status': 'error',
                    'message': str(e)
                }
                self.logger.error(f"❌ {device_name}: ошибка - {str(e)}")
                if show_progress:
                    print(f"   ❌ Ошибка: {str(e)}")
        
        if show_progress:
            success_count = sum(1 for r in results.values() if r.get('status') == 'success')
            failed_count = sum(1 for r in results.values() if r.get('status') != 'success')
            
            print(f"\n📊 ИТОГИ СОЗДАНИЯ БЭКАПОВ:")
            print(f"   ✅ Успешно: {success_count} устройств")
            print(f"   ❌ Ошибок: {failed_count} устройств")
            print(f"   📦 Всего обработано: {len(results)} устройств")
        
        if config.get('telegram_report', False):
            self._send_backup_report(results)

    def _send_backup_report(self, results: Dict[str, Any]):
        """Отправка детального отчета о создании бэкапов"""
        report = self.reporter.create_backup_report(results)
        
        if self.reporter.send_telegram_message(report):
            self.logger.info("📤 Детальный отчет о бэкапах отправлен в Telegram")
        else:
            self.logger.error("❌ Ошибка отправки отчета о бэкапах в Telegram")

    def setup_schedules(self):
        scheduler_config = self.scheduler_config.get('scheduler', {})
        
        schedule.clear()
        
        version_config = scheduler_config.get('version_check', {})
        if version_config.get('enabled', False):
            time_str = version_config.get('time', '09:00')
            days = version_config.get('days', [])
            
            if not days or 'everyday' in days:
                schedule.every().day.at(time_str).do(self.task_version_check)
                self.logger.info(f"📅 Настроена ежедневная проверка версий на {time_str}")
            else:
                for day in days:
                    getattr(schedule.every(), day.lower()).at(time_str).do(self.task_version_check)
                self.logger.info(f"📅 Настроена проверка версий на {time_str} по дням: {', '.join(days)}")
        
        update_config = scheduler_config.get('update_check', {})
        if update_config.get('enabled', False):
            time_str = update_config.get('time', '10:00')
            days = update_config.get('days', [])
            
            if not days or 'everyday' in days:
                schedule.every().day.at(time_str).do(self.task_update_check)
                self.logger.info(f"📅 Настроена ежедневная проверка обновлений на {time_str}")
            else:
                for day in days:
                    getattr(schedule.every(), day.lower()).at(time_str).do(self.task_update_check)
                self.logger.info(f"📅 Настроена проверка обновлений на {time_str} по дням: {', '.join(days)}")
        
        auto_update_config = scheduler_config.get('auto_update', {})
        if auto_update_config.get('enabled', False):
            time_str = auto_update_config.get('time', '23:00')
            days = auto_update_config.get('days', [])
            
            if not days or 'everyday' in days:
                schedule.every().day.at(time_str).do(self.task_auto_update)
                self.logger.info(f"📅 Настроено ежедневное автоматическое обновление на {time_str}")
            else:
                for day in days:
                    getattr(schedule.every(), day.lower()).at(time_str).do(self.task_auto_update)
                self.logger.info(f"📅 Настроено автоматическое обновление на {time_str} по дням: {', '.join(days)}")
        
        backup_config = scheduler_config.get('auto_backup', {})
        if backup_config.get('enabled', False):
            time_str = backup_config.get('time', '02:00')
            days = backup_config.get('days', [])
            
            if not days or 'everyday' in days:
                schedule.every().day.at(time_str).do(self.task_create_backups)
                self.logger.info(f"📅 Настроено ежедневное создание бэкапов на {time_str}")
            else:
                for day in days:
                    getattr(schedule.every(), day.lower()).at(time_str).do(self.task_create_backups)
                self.logger.info(f"📅 Настроено создание бэкапов на {time_str} по дням: {', '.join(days)}")

    def start_scheduler(self):
        if self.is_running:
            self.logger.warning("⚠️ Планировщик уже запущен")
            return
        
        self.is_running = True
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.scheduler_thread.start()
        
        self.logger.info("🚀 Планировщик задач запущен")
        print("🚀 Планировщик задач запущен в фоновом режиме")

    def stop_scheduler(self):
        self.is_running = False
        schedule.clear()
        self.logger.info("🛑 Планировщик задач остановлен")
        print("🛑 Планировщик задач остановлен")

    def _scheduler_loop(self):
        while self.is_running:
            try:
                schedule.run_pending()
                time.sleep(1)
            except Exception as e:
                self.logger.error(f"❌ Ошибка в цикле планировщика: {str(e)}")
                time.sleep(60)

    def print_schedule_status(self):
        print("\n📅 Запланированные задачи")
        print("=" * 50)
        
        if not self.is_running:
            print("❌ Планировщик остановлен")
            return
        
        print("✅ Планировщик запущен")
        print("\nЗапланированные задачи:")
        print("-" * 30)
        
        jobs = schedule.get_jobs()
        if not jobs:
            print("Нет активных задач")
            return
        
        for i, job in enumerate(jobs, 1):
            next_run = job.next_run.strftime("%d.%m.%Y %H:%M:%S") if job.next_run else "Не запланировано"
            task_name = job.job_func.__name__.replace('task_', '').replace('_', ' ').title()
            print(f"{i}. {task_name}")
            print(f"   Следующий запуск: {next_run}")
            print()

    def get_scheduler_config(self) -> Dict[str, Any]:
        return self.scheduler_config.copy()
