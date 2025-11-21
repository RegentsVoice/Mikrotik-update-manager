import os
import sys
import signal
import yaml
import time
from datetime import datetime
from core.connector import MikroTikSSHConnector
from core.updater import MikroTikUpdater
from core.reporter import ReportManager
from core.scheduler import TaskScheduler
from core.backup_manager import BackupManager

class MikroTikManager:
    def __init__(self):
        self.logging_config = self._load_logging_config()
        self.connector = MikroTikSSHConnector(
            enable_logging=self.logging_config.get('console_logging', True)
        )
        self.updater = MikroTikUpdater(self.connector)
        self.reporter = ReportManager()
        self.scheduler = TaskScheduler(self.connector, self.updater, self.reporter)
        self.backup_manager = BackupManager(self.connector)
        self._setup_signal_handlers()
        
        if not self.connector.devices:
            print("❌ Ошибка: Не удалось загрузить конфигурацию устройств")
            print("Проверьте файл config/devices.yaml")
            sys.exit(1)

    def _load_logging_config(self) -> Dict[str, Any]:
        """Загрузка конфигурации логирования"""
        try:
            with open('config/scheduler.yaml', 'r', encoding='utf-8') as file:
                config = yaml.safe_load(file)
            return config.get('notifications', {})
        except Exception as e:
            print(f"⚠️ Не удалось загрузить конфигурацию логирования: {e}")
            return {'console_logging': True, 'log_to_file': True}

    def _setup_signal_handlers(self):
        """Настройка обработчиков сигналов для корректного выхода"""
        def signal_handler(signum, frame):
            self.cleanup()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        if hasattr(signal, 'SIGQUIT'):
            signal.signal(signal.SIGQUIT, signal_handler)

    def cleanup(self):
        print("\n🛑 Завершение работы...")
        self.scheduler.stop_scheduler()

    def get_all_versions(self) -> dict:
        results = {}
        
        for device_name in self.connector.devices.keys():
            print(f"🔍 Проверка {device_name}...")
            
            if not self.connector.test_connection(device_name):
                results[device_name] = {
                    'status': 'offline',
                    'message': 'Устройство недоступно'
                }
                continue
            
            device_info = self.connector.get_routeros_info(device_name)
            
            if 'error' in device_info:
                results[device_name] = {
                    'status': 'error',
                    'message': device_info['error']
                }
            else:
                results[device_name] = {
                    'status': 'online',
                    'current_version': device_info.get('version', 'Неизвестно'),
                    'identity': device_info.get('identity', 'Неизвестно'),
                    'model': device_info.get('model', 'Неизвестно'),
                    **device_info
                }
        
        return results

    def check_updates_all(self) -> dict:
        """Проверка обновлений на всех устройствах"""
        return self.updater.check_all_devices()

    def show_updates_report(self, updates: dict):
        """Показать отчет об обновлениях в консоли"""
        print("\n" + "="*60)
        print("ОТЧЕТ ОБ ОБНОВЛЕНИЯХ MIKROTIK")
        print("="*60)
        
        updates_available = 0
        online_count = 0
        version_stats = {}
        
        for device_name, info in updates.items():
            status = "Онлайн" if info.get('status') == 'online' else "Оффлайн"
            status_icon = "🟢" if info.get('status') == 'online' else "🔴"
            update_available = info.get('update_available', False)
            
            if info.get('status') == 'online':
                online_count += 1
                current_version = info.get('current_version', 'Неизвестно')
                if current_version != 'Неизвестно':
                    version_short = current_version.split()[0]
                    if version_short in version_stats:
                        version_stats[version_short] += 1
                    else:
                        version_stats[version_short] = 1
                
                if update_available:
                    updates_available += 1
                    update_icon = "🔄"
                    update_status = "ТРЕБУЕТ ОБНОВЛЕНИЯ"
                else:
                    update_icon = "✅"
                    update_status = "АКТУАЛЬНА"
            else:
                update_icon = "❌"
                update_status = "НЕДОСТУПНО"
            
            print(f"\n{status_icon} Устройство: {device_name}")
            print(f"   Статус: {status}")
            
            if info.get('status') == 'online':
                print(f"   Текущая версия: {info.get('current_version', 'Неизвестно')}")
                print(f"   Последняя версия: {info.get('latest_version', 'Неизвестно')}")
                print(f"   Статус: {update_icon} {update_status}")
            else:
                print(f"   Ошибка: {info.get('message', 'Устройство недоступно')}")
        
        print(f"\n📊 СВОДКА:")
        print(f"   • Всего устройств: {len(updates)}")
        print(f"   • Онлайн: {online_count}")
        print(f"   • Требуют обновления: {updates_available}")
        
        if version_stats:
            print(f"   • Распределение версий:")
            for version, count in sorted(version_stats.items()):
                print(f"     - {version}: {count} устройств")

    def update_selected_device(self, device_name: str):
        if device_name not in self.connector.devices:
            print(f"❌ Устройство {device_name} не найдено")
            return
        
        print(f"🔄 Начало обновления {device_name}...")
        
        update_info = self.updater.check_for_updates(device_name)
        
        if not update_info.get('available'):
            print(f"✅ Для {device_name} обновления не требуются")
            return
        
        print(f"🔄 Найдено обновление: {update_info['current_version']} → {update_info['latest_version']}")

        result = self.updater.install_update(device_name)
        
        if result['success']:
            print(f"✅ {device_name} успешно обновлен")
            
            message = f"✅ <b>Устройство обновлено</b>\n\n"
            message += f"Устройство: <b>{device_name}</b>\n"
            message += f"Версия: {update_info['current_version']} → {update_info['latest_version']}\n"
            message += f"Бэкап: {backup_name}\n"
            message += f"Время: {datetime.now().strftime('%d.%m.%Y %H:%M')}"
            
            if self.reporter.send_telegram_message(message):
                print("📤 Отчет отправлен в Telegram")
            else:
                print("⚠️ Не удалось отправить отчет в Telegram")
        else:
            print(f"❌ Ошибка обновления {device_name}: {result['message']}")

    def manage_backups_menu(self):
        while True:
            print("="*50)
            print("        УПРАВЛЕНИЕ БЭКАПАМИ")
            print("="*50)
            print("1. 📋 Список бэкапов на устройствах")
            print("2. 💾 Создать бэкап на устройстве")
            print("3. 🗑️  Удалить старые бэкапы")
            print("4. ↩️  Назад в главное меню")
            
            try:
                choice = input("\nВыберите действие (1-4): ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\n\n↩️  Возврат в главное меню...")
                break
            
            if choice == '1':
                self.list_backups_all_devices()
            
            elif choice == '2':
                self.create_backup_manual()
            
            elif choice == '3':
                self.delete_backups_manual()
            
            elif choice == '4':
                break
            
            else:
                print("❌ Неверный выбор")
            
            try:
                input("\nНажмите Enter для продолжения...")
            except (KeyboardInterrupt, EOFError):
                print("\n")
                continue

    def list_backups_all_devices(self):
        print("\n📋 Бэкапы на устройствах (префикс mum_):")
        print("=" * 50)
        
        for device_name in self.connector.devices.keys():
            print(f"\n🔍 {device_name}:")
            
            if not self.connector.test_connection(device_name):
                print("   ❌ Устройство недоступно")
                continue
            
            backups = self.backup_manager.list_backups(device_name)
            
            if backups:
                for backup in backups:
                    print(f"   💾 {backup}")
            else:
                print("   📭 Бэкапы не найдены")

    def create_backup_manual(self):
        print("\n📋 Доступные устройства:")
        devices = list(self.connector.devices.keys())
        for i, device in enumerate(devices, 1):
            print(f"   {i}. {device}")
        
        try:
            device_choice = input("\nВыберите устройство (номер): ").strip()
            if device_choice.lower() in ['q', 'quit', 'exit']:
                return
            device_choice = int(device_choice) - 1
            if 0 <= device_choice < len(devices):
                device_name = devices[device_choice]
                
                comment = input("Комментарий для бэкапа (необязательно): ").strip()
                
                print(f"💾 Создание бэкапа для {device_name}...")
                
                existing_backups = self.backup_manager.list_backups(device_name)
                if existing_backups:
                    print(f"📁 Существующие бэкапы: {existing_backups}")
                
                success, backup_name = self.backup_manager.create_backup_direct(device_name, comment)
                
                if success:
                    print(f"✅ Бэкап успешно создан: {backup_name}")
                    
                    # Отправляем уведомление в Telegram
                    message = f"💾 <b>Создан новый бэкап</b>\n\n"
                    message += f"Устройство: <b>{device_name}</b>\n"
                    message += f"Бэкап: {backup_name}\n"
                    message += f"Время: {datetime.now().strftime('%d.%m.%Y %H:%M')}"
                    
                    if self.reporter.send_telegram_message(message):
                        print("📤 Уведомление отправлено в Telegram")
                else:
                    print("❌ Ошибка создания бэкапа")
                    
                    current_backups = self.backup_manager.list_backups(device_name)
                    if current_backups:
                        print(f"📁 Текущие бэкапы на устройстве: {current_backups}")
            else:
                print("❌ Неверный выбор")
        except (ValueError, KeyboardInterrupt, EOFError):
            print("❌ Введите номер устройства или 'q' для выхода")

    def delete_backups_manual(self):
        print("\n📋 Доступные устройства:")
        devices = list(self.connector.devices.keys())
        for i, device in enumerate(devices, 1):
            print(f"   {i}. {device}")
        
        try:
            device_choice = input("\nВыберите устройство (номер): ").strip()
            if device_choice.lower() in ['q', 'quit', 'exit']:
                return
            device_choice = int(device_choice) - 1
            if 0 <= device_choice < len(devices):
                device_name = devices[device_choice]
                
                backups = self.backup_manager.list_backups(device_name)
                if not backups:
                    print("📭 Бэкапы не найдены")
                    return
                
                print(f"\n🗑️ Будут удалены следующие бэкапы:")
                for backup in backups:
                    print(f"   • {backup}")
                
                confirm = input("\n❓ Подтвердите удаление (y/n): ").lower().strip()
                if confirm == 'y':
                    print("💥 Запуск удаления бэкапов...")
                    deleted_count = self.backup_manager.delete_old_backups(device_name)
                    
                    print(f"✅ Удалено бэкапов: {deleted_count}/{len(backups)}")
                    
                    remaining = self.backup_manager.list_backups(device_name)
                    if remaining:
                        print(f"📁 Оставшиеся бэкапы: {remaining}")
                    else:
                        print("✅ Все бэкапы удалены")
                else:
                    print("❌ Удаление отменено")
            else:
                print("❌ Неверный выбор")
        except (ValueError, KeyboardInterrupt, EOFError):
            print("❌ Введите номер устройства или 'q' для выхода")

    def manage_scheduler(self):
        while True:
            print("\n" + "="*50)
            print("УПРАВЛЕНИЕ ПЛАНИРОВЩИКОМ")
            print("="*50)
            print("1. 🚀  Запустить планировщик")
            print("2. ⏸️  Остановить планировщик")
            print("3. 📊  Запланированные задачи")
            print("4. 📊  Статус задач планировшика")
            print("5. 🔄  Перезагрузить конфигурацию")
            print("6. ↩️  Назад в главное меню")
            
            try:
                choice = input("\nВыберите действие (1-6): ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\n\n↩️  Возврат в главное меню...")
                break
            
            if choice == '1':
                self.scheduler.setup_schedules()
                self.scheduler.start_scheduler()
                try:
                    input("\nНажмите Enter для продолжения...")
                except (KeyboardInterrupt, EOFError):
                    print("\n")
                    continue
            
            elif choice == '2':
                self.scheduler.stop_scheduler()
                try:
                    input("\nНажмите Enter для продолжения...")
                except (KeyboardInterrupt, EOFError):
                    print("\n")
                    continue
            
            elif choice == '3':
                self.scheduler.print_schedule_status()
                try:
                    input("\nНажмите Enter для продолжения...")
                except (KeyboardInterrupt, EOFError):
                    print("\n")
                    continue
            
            elif choice == '4':
                self.show_scheduler_config()
                try:
                    input("\nНажмите Enter для продолжения...")
                except (KeyboardInterrupt, EOFError):
                    print("\n")
                    continue
            
            elif choice == '5':
                self.scheduler.scheduler_config = self.scheduler._load_scheduler_config()
                self.scheduler.setup_schedules()
                print("✅ Конфигурация перезагружена")
                try:
                    input("\nНажмите Enter для продолжения...")
                except (KeyboardInterrupt, EOFError):
                    print("\n")
                    continue
            
            elif choice == '6':
                break
            
            else:
                print("❌ Неверный выбор")
                try:
                    input("Нажмите Enter для продолжения...")
                except (KeyboardInterrupt, EOFError):
                    print("\n")
                    continue

    def show_scheduler_config(self):
        config = self.scheduler.scheduler_config
        
        print("\n📋 Статус задач планировшика:")
        print("=" * 50)
        
        scheduler_config = config.get('scheduler', {})
        
        for task_name, task_config in scheduler_config.items():
            enabled = "✅ ВКЛ" if task_config.get('enabled') else "❌ ВЫКЛ"
            print(f"\n{task_name.replace('_', ' ').title()}: {enabled}")
            
            if task_config.get('enabled'):
                if 'time' in task_config:
                    print(f"   Время: {task_config['time']}")
                if 'days' in task_config:
                    print(f"   Дни: {', '.join(task_config['days'])}")
                if 'interval' in task_config:
                    print(f"   Интервал: {task_config['interval']} мин")
                if 'devices' in task_config:
                    print(f"   Устройства: {', '.join(task_config['devices'])}")

    def run_manual_task(self):
        print("\n" + "="*50)
        print("РУЧНОЙ ЗАПУСК ЗАДАЧ")
        print("="*50)
        print("1. 📋  Проверить версии устройств")
        print("2. 🔄  Проверить обновления")
        print("3. 🚀  Запустить автоматическое обновление")
        print("4. 💾  Создать бэкапы на всех устройствах")
        print("5. ↩️  Назад")
        
        try:
            choice = input("\nВыберите задачу (1-6): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\n↩️  Возврат в главное меню...")
            return
        
        if choice == '1':
            print("\n🔄 Запуск проверки версий...")
            self.scheduler.task_version_check(show_progress=True)
        
        elif choice == '2':
            print("\n🔄 Запуск проверки обновлений...")
            self.scheduler.task_update_check(show_progress=True)
        
        elif choice == '3':
            print("\n🔄 Запуск автоматического обновления...")
            try:
                confirm = input("❓ Вы уверены? Это обновит устройства! (y/n): ").lower().strip()
                if confirm == 'y':
                    self.scheduler.task_auto_update()
                else:
                    print("❌ Операция отменена")
            except (KeyboardInterrupt, EOFError):
                print("\n\n❌ Операция отменена")
        
        
        elif choice == '4':
            print("\n💾 Создание бэкапов на всех устройствах...")
            self.scheduler.task_create_backups(show_progress=True)
        
        elif choice == '5':
            return
        
        else:
            print("❌ Неверный выбор")
        
        try:
            input("\nНажмите Enter для продолжения...")
        except (KeyboardInterrupt, EOFError):
            print("\n")
            return

    def send_full_report(self):
        print("\n📊 Сбор отчета...")
        
        versions = self.get_all_versions()
        updates = self.check_updates_all()
        
        report = "📊 <b>Отчет MikroTik</b>\n"
        report += f"📅 Дата: {datetime.now().strftime('%d.%m.%Y %H:%M')}\n"
        report += "─" * 40 + "\n\n"
        
        online_count = 0
        update_count = 0
        version_stats = {}
        
        for device_name in self.connector.devices.keys():
            version_info = versions.get(device_name, {})
            update_info = updates.get(device_name, {})
            
            if version_info.get('status') == 'online':
                online_count += 1
                status_icon = "🟢"
                
                current_version = version_info.get('current_version', 'Неизвестно')
                
                if current_version != 'Неизвестно':
                    version_short = current_version.split()[0]
                    if version_short in version_stats:
                        version_stats[version_short] += 1
                    else:
                        version_stats[version_short] = 1
                
                if update_info.get('update_available'):
                    update_count += 1
                    update_icon = "🔄"
                    update_text = f"Требуется обновление: {update_info.get('latest_version', 'Неизвестно')}"
                else:
                    update_icon = "✅"
                    update_text = "Система актуальна"
                
                report += f"{status_icon} <b>{device_name}</b>\n"
                report += f"   📋 Версия: {current_version}\n"
                report += f"   📊 Обновление: {update_icon} {update_text}\n"
                
                if version_info.get('identity'):
                    report += f"   🏷️ Имя: {version_info['identity']}\n"
                if version_info.get('model'):
                    report += f"   💻 Модель: {version_info['model']}\n"
                
                report += "\n"
            else:
                report += f"🔴 <b>{device_name}</b>\n"
                report += f"   ❌ Устройство недоступно: {version_info.get('message', 'Неизвестно')}\n\n"
        
        report += "📈 <b>Статистика:</b>\n"
        report += f"• Всего устройств: {len(self.connector.devices)}\n"
        report += f"• Онлайн: {online_count}\n"
        report += f"• Оффлайн: {len(self.connector.devices) - online_count}\n"
        report += f"• Требуют обновления: {update_count}\n"
        report += f"• Актуальны: {online_count - update_count}\n"
        
        if version_stats:
            report += f"• Распределение версий:\n"
            for version, count in sorted(version_stats.items()):
                report += f"   - {version}: {count} устройств\n"
        
        if self.reporter.send_telegram_message(report):
            print("✅ Детальный отчет отправлен в Telegram")
        else:
            print("❌ Ошибка отправки отчета в Telegram")

    def print_menu(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        
        scheduler_status = "✅ Запущен" if self.scheduler.is_running else "❌ Остановлен"
        
        print("="*60)
        print("MIKROTIK UPDATE MANAGER")
        print("="*60)
        print(f"📊 Устройств: {len(self.connector.devices)}")
        print(f"📅 Планировщик: {scheduler_status}")
        print()
        print("1. 📋 Получить версии всех устройств")
        print("2. 🔄 Проверить обновления")
        print("3. 🔄 Обновить выбранное устройство")
        print("4. 💾 Управление бэкапами")
        print("5. 📤 Отправить отчет в Telegram")
        print("6. ⏰ Управление планировщиком")
        print("7. 🚀 Ручной запуск задач")
        print("8. 🚪 Выход")
        print()
        print("="*60)

    def main(self):
        self.scheduler.setup_schedules()
        self.scheduler.start_scheduler()
        
        while True:
            self.print_menu()
            try:
                choice = input("Выберите действие (1-8): ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\n\n🛑 Завершение работы...")
                self.cleanup()
                break
            
            if choice == '1':
                print("\n🔄 Получение информации о версиях...")
                versions = self.get_all_versions()
                self.reporter.print_console_report(versions, "versions")
                
                try:
                    send_tg = input("\n📤 Отправить отчет в Telegram? (y/n): ").lower().strip()
                    if send_tg == 'y':
                        report = self.reporter.create_version_report(versions)
                        if self.reporter.send_telegram_message(report):
                            print("✅ Детальный отчет отправлен в Telegram")
                        else:
                            print("❌ Ошибка отправки отчета в Telegram")
                except (KeyboardInterrupt, EOFError):
                    print("\n")
                
                try:
                    input("\nНажмите Enter для продолжения...")
                except (KeyboardInterrupt, EOFError):
                    print("\n")
                    continue
            
            elif choice == '2':
                print("\n🔄 Проверка обновлений...")
                updates = self.check_updates_all()
                
                self.show_updates_report(updates)
                
                try:
                    send_tg = input("\n📤 Отправить отчет в Telegram? (y/n): ").lower().strip()
                    if send_tg == 'y':
                        report = self.reporter.create_update_report(updates)
                        
                        if self.reporter.send_telegram_message(report):
                            print("✅ Детальный отчет отправлен в Telegram")
                        else:
                            print("❌ Ошибка отправки отчета в Telegram")
                except (KeyboardInterrupt, EOFError):
                    print("\n")
                
                try:
                    input("\nНажмите Enter для продолжения...")
                except (KeyboardInterrupt, EOFError):
                    print("\n")
                    continue
            
            elif choice == '3':
                print("\n📋 Доступные устройства:")
                devices = list(self.connector.devices.keys())
                for i, device in enumerate(devices, 1):
                    print(f"   {i}. {device}")
                
                try:
                    device_choice = input("\nВыберите устройство (номер): ").strip()
                    if device_choice.lower() in ['q', 'quit', 'exit']:
                        continue
                    device_choice = int(device_choice) - 1
                    if 0 <= device_choice < len(devices):
                        self.update_selected_device(devices[device_choice])
                    else:
                        print("❌ Неверный выбор")
                except (ValueError, KeyboardInterrupt, EOFError):
                    print("❌ Введите номер устройства или 'q' для выхода")
                
                try:
                    input("\nНажмите Enter для продолжения...")
                except (KeyboardInterrupt, EOFError):
                    print("\n")
                    continue
            
            elif choice == '4':
                self.manage_backups_menu()
            
            elif choice == '5':
                self.send_full_report()
                try:
                    input("\nНажмите Enter для продолжения...")
                except (KeyboardInterrupt, EOFError):
                    print("\n")
                    continue
            
            elif choice == '6':
                self.manage_scheduler()
            
            elif choice == '7':
                self.run_manual_task()
            
            elif choice == '8':
                print("\n🛑 Выход из программы...")
                self.cleanup()
                break
            
            else:
                print("❌ Неверный выбор. Попробуйте снова.")
                try:
                    input("Нажмите Enter для продолжения...")
                except (KeyboardInterrupt, EOFError):
                    print("\n")
                    continue

if __name__ == "__main__":
    manager = MikroTikManager()
    try:
        manager.main()
    except KeyboardInterrupt:
        print("\n\n🛑 Завершение работы...")
        manager.cleanup()
    except EOFError:
        print("\n\n🛑 Завершение работы...")
        manager.cleanup()
