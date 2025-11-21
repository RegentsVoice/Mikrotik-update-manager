import time
import re
import logging
from typing import Dict, List, Tuple
from .connector import MikroTikSSHConnector


class BackupManager:
    def __init__(self, connector: MikroTikSSHConnector):
        self.connector = connector
        self.logger = logging.getLogger("backup")
        self.prefix = "mum_"

        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
            self.logger.addHandler(h)
            self.logger.setLevel(logging.INFO)


    def _generate_name(self, comment: str = "") -> str:
        ts = time.strftime("%m%d_%H%M")
        base = f"{self.prefix}{ts}"

        if comment:
            clean = re.sub(r"[^\w]", "", comment)[:10]
            base += f"_{clean}"

        return base[:20]

    def _find_backup(self, device: str, base_name: str) -> str:
        files, _ = self.connector.execute_command(device, "/file print")

        for line in files:
            if base_name in line and ".backup" in line.lower():
                m = re.search(r"(\S+\.backup)", line)
                if m:
                    return m.group(1)

        return ""


    def list_backups(self, device: str) -> List[str]:
        out, _ = self.connector.execute_command(
            device,
            f'/file print where name~"{self.prefix}"'
        )
        backups = []

        for line in out:
            m = re.search(rf"({self.prefix}\S+\.backup)", line)
            if m:
                backups.append(m.group(1))

        return backups


    def delete_old_backups(self, device: str) -> int:
        backups = self.list_backups(device)
        removed = 0

        for b in backups:
            self.logger.info(f"Удаление старого бэкапа: {b}")
            self.connector.execute_command(device, f'/file remove "{b}"')
            time.sleep(0.5)

        remaining = self.list_backups(device)
        removed = len(backups) - len(remaining)

        return removed


    def create_backup(self, device: str, comment: str = "") -> Tuple[bool, str]:
        try:
            self.logger.info(f"Создание бэкапа на {device}")

            self.delete_old_backups(device)

            name = self._generate_name(comment)
            cmd = f'/system backup save name="{name}"'

            self.logger.info(f"Команда: {cmd}")
            out, err = self.connector.execute_command(device, cmd)

            if any("error" in e.lower() for e in err):
                self.logger.error(f"RouterOS ERROR: {err}")
                return False, ""

            for _ in range(10):
                time.sleep(2)
                real = self._find_backup(device, name)
                if real:
                    self.logger.info(f"Бэкап создан: {real}")
                    return True, real

            self.logger.error("Бэкап не появился, вывод /file print:")
            files, _ = self.connector.execute_command(device, "/file print")
            for ln in files:
                self.logger.error(ln)

            return False, ""

        except Exception as e:
            self.logger.error(f"Ошибка создания бэкапа: {str(e)}")
            return False, ""

    def get_backup_info(self, device: str) -> Dict[str, any]:
        backups = self.list_backups(device)
        info = []

        for b in backups:
            out, _ = self.connector.execute_command(
                device, f'/file print where name="{b}"'
            )
            info.append({"name": b, "raw": out})

        return {
            "count": len(backups),
            "backups": info,
        }
