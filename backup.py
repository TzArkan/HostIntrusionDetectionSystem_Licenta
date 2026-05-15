import socket
import os
import time
from datetime import datetime


class DestinatiBackup:
    def trimite(self, alerta: dict) -> bool:
        raise NotImplementedError

    def _formateaza_mesaj(self, alerta: dict) -> str:
        ora       = datetime.fromtimestamp(alerta.get("timestamp", time.time())).strftime("%Y-%m-%d %H:%M:%S")
        severitate = alerta.get("severitate", "INFO")
        tip        = alerta.get("tip_atac",   "NECUNOSCUT")
        src        = alerta.get("src_ip",     "-")
        dst        = alerta.get("dst_ip",     "-")
        detalii    = alerta.get("detalii",    "")

        return f"[HIDS] {ora} [{severitate}] {tip} | src={src} dst={dst} | {detalii}"



class BackupSyslogVM(DestinatiBackup):
    _SEVERITATE_MAP = {
        "SCAZUTA":  6,   # informational
        "MEDIE":    4,   # warning
        "RIDICATA": 3,   # error
        "CRITICA":  2,   # critical
    }

    def __init__(self, host: str, port: int = 514, protocol: str = "UDP", timeout: float = 2.0):
        self.host     = host
        self.port     = port
        self.protocol = protocol.upper()
        self.timeout  = timeout

    def trimite(self, alerta: dict) -> bool:
        try:
            mesaj  = self._construieste_syslog(alerta)
            octeti = mesaj.encode("utf-8")

            if self.protocol == "UDP":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(octeti, (self.host, self.port))
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.connect((self.host, self.port))
                    sock.sendall(octeti + b"\n")

            return True

        except (socket.error, OSError) as e:
            print(f"[BACKUP-SYSLOG] Eroare trimitere catre {self.host}:{self.port} -> {e}")
            return False

    def _construieste_syslog(self, alerta: dict) -> str:
        sev_num   = self._SEVERITATE_MAP.get(alerta.get("severitate", "MEDIE"), 4)
        prioritate = 1 * 8 + sev_num   

        ora      = datetime.fromtimestamp(alerta.get("timestamp", time.time())).strftime("%b %d %H:%M:%S")
        hostname = socket.gethostname()
        mesaj    = self._formateaza_mesaj(alerta)

        return f"<{prioritate}>{ora} {hostname} HIDS: {mesaj}"



class BackupFolderLocal(DestinatiBackup):

    def __init__(self, cale: str):
        self.cale = cale
        director = os.path.dirname(os.path.abspath(cale))
        os.makedirs(director, exist_ok=True)

    def trimite(self, alerta: dict) -> bool:
        try:
            mesaj = self._formateaza_mesaj(alerta)
            with open(self.cale, "a", encoding="utf-8") as f:
                f.write(mesaj + "\n")
            return True
        except OSError as e:
            print(f"[BACKUP-LOCAL] Eroare scriere in '{self.cale}' -> {e}")
            return False

    def verifica_disponibil(self) -> bool:
        try:
            director = os.path.dirname(os.path.abspath(self.cale))
            return os.path.exists(director)
        except OSError:
            return False



class BackupMultiplu(DestinatiBackup):
    def __init__(self, destinatii: list):
        self.destinatii = destinatii

    def trimite(self, alerta: dict) -> bool:
        rezultate = [dest.trimite(alerta) for dest in self.destinatii]
        return any(rezultate)

    def adauga_destinatie(self, destinatie: DestinatiBackup):
        self.destinatii.append(destinatie)



class BackupNoop(DestinatiBackup):
    def trimite(self, alerta: dict) -> bool:
        return True   
