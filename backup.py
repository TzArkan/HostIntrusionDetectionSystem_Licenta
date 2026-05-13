"""
backup.py - Destinatii de backup pentru alerte
Ierarhie OOP:
  DestinatiBackup  (clasa de baza abstracta)
    ├── BackupSyslogVM      (trimite UDP/TCP catre rsyslog pe VM)
    ├── BackupFolderLocal   (scrie intr-un fisier .log pe disk local / extern / USB)
    └── BackupMultiplu      (trimite catre mai multe destinatii simultan)
  BackupNoop                (nu face nimic - Null Object pattern)

Utilizare in main.py:
    backup = BackupMultiplu([
        BackupSyslogVM(host="192.168.1.100", port=514),
        BackupFolderLocal(cale="D:/backup_hids/alerte.log"),
    ])
    backup.trimite(alerta_dict)
"""

import socket
import os
import time
from datetime import datetime


class DestinatiBackup:
    """
    Clasa abstracta de baza pentru destinatii de backup.
    Toate subclasele trebuie sa implementeze metoda trimite().
    """
    def trimite(self, alerta: dict) -> bool:
        """
        Trimite o alerta catre destinatie.

        Parametru:
            alerta - dict cu cheile:
                     tip_atac, severitate, src_ip, dst_ip, detalii, timestamp

        Returneaza:
            True daca trimiterea a reusit, False altfel.
        """
        raise NotImplementedError

    def _formateaza_mesaj(self, alerta: dict) -> str:
        """
        Formateaza alerta intr-un sir de caractere standard.
        Folosit intern de subclase pentru a nu duplica logica.
        """
        ora       = datetime.fromtimestamp(alerta.get("timestamp", time.time())).strftime("%Y-%m-%d %H:%M:%S")
        severitate = alerta.get("severitate", "INFO")
        tip        = alerta.get("tip_atac",   "NECUNOSCUT")
        src        = alerta.get("src_ip",     "-")
        dst        = alerta.get("dst_ip",     "-")
        detalii    = alerta.get("detalii",    "")

        return f"[HIDS] {ora} [{severitate}] {tip} | src={src} dst={dst} | {detalii}"



class BackupSyslogVM(DestinatiBackup):
    """
    Trimite alertele catre serverul rsyslog de pe VM Ubuntu.
    Suporta UDP (implicit, fara garantie de livrare) si TCP (garanteaza livrarea).

    Formatul mesajului respecta RFC 3164 (syslog clasic):
        <prioritate>timestamp hostname HIDS: mesaj
    """

    # Prioritati syslog (RFC 3164): prioritate = facility * 8 + severitate_num
    # Facility 1 = user-level messages
    _SEVERITATE_MAP = {
        "SCAZUTA":  6,   # informational
        "MEDIE":    4,   # warning
        "RIDICATA": 3,   # error
        "CRITICA":  2,   # critical
    }

    def __init__(self, host: str, port: int = 514, protocol: str = "UDP", timeout: float = 2.0):
        """
        host     - adresa IP a VM-ului Ubuntu (ex: "192.168.1.100")
        port     - portul rsyslog (implicit 514)
        protocol - "UDP" (rapid, fara garantie) sau "TCP" (garanteaza livrarea)
        timeout  - timeout pentru conexiunea TCP, in secunde
        """
        self.host     = host
        self.port     = port
        self.protocol = protocol.upper()
        self.timeout  = timeout

    def trimite(self, alerta: dict) -> bool:
        """Trimite alerta catre rsyslog prin UDP sau TCP."""
        try:
            mesaj  = self._construieste_syslog(alerta)
            octeti = mesaj.encode("utf-8")

            if self.protocol == "UDP":
                # UDP: connectionless, trimitem direct fara a stabili conexiune
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(octeti, (self.host, self.port))
            else:
                # TCP: stabilim conexiune, trimitem mesajul, inchidem
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.connect((self.host, self.port))
                    # newline la sfarsit = delimitator de mesaj in TCP syslog
                    sock.sendall(octeti + b"\n")

            return True

        except (socket.error, OSError) as e:
            print(f"[BACKUP-SYSLOG] Eroare trimitere catre {self.host}:{self.port} -> {e}")
            return False

    def _construieste_syslog(self, alerta: dict) -> str:
        """
        Construieste mesajul in format syslog RFC 3164.
        Format: <prioritate>MMM DD HH:MM:SS hostname tag: mesaj
        """
        sev_num   = self._SEVERITATE_MAP.get(alerta.get("severitate", "MEDIE"), 4)
        prioritate = 1 * 8 + sev_num   # facility=1 (user), severitate variabila

        ora      = datetime.fromtimestamp(alerta.get("timestamp", time.time())).strftime("%b %d %H:%M:%S")
        hostname = socket.gethostname()
        mesaj    = self._formateaza_mesaj(alerta)

        return f"<{prioritate}>{ora} {hostname} HIDS: {mesaj}"



class BackupFolderLocal(DestinatiBackup):
    """
    Scrie alertele intr-un fisier .log pe disk.
    Functioneaza pentru orice cale accesibila din Windows:
        - folder local   : "C:/Users/User/Desktop/hids/alerte.log"
        - disk extern    : "D:/backup/alerte.log"
        - USB            : "E:/alerte.log"
        - retea locala   : "//NAS/backup/alerte.log"

    Directorul este creat automat daca nu exista.
    Fisierul este deschis in mod 'append' (nu se suprascrie continutul existent).
    """

    def __init__(self, cale: str):
        """
        cale - calea completa catre fisierul de log.
        """
        self.cale = cale
        # os.makedirs cu exist_ok=True creeaza toate directoarele intermediare
        # si nu arunca eroare daca directorul exista deja
        director = os.path.dirname(os.path.abspath(cale))
        os.makedirs(director, exist_ok=True)

    def trimite(self, alerta: dict) -> bool:
        """Adauga alerta la sfarsitul fisierului de log."""
        try:
            mesaj = self._formateaza_mesaj(alerta)
            # 'a' = append mode: adauga la sfarsit fara a sterge continutul
            with open(self.cale, "a", encoding="utf-8") as f:
                f.write(mesaj + "\n")
            return True
        except OSError as e:
            print(f"[BACKUP-LOCAL] Eroare scriere in '{self.cale}' -> {e}")
            return False

    def verifica_disponibil(self) -> bool:
        """Verifica daca disk-ul/directorul destinatie este accesibil."""
        try:
            director = os.path.dirname(os.path.abspath(self.cale))
            return os.path.exists(director)
        except OSError:
            return False



class BackupMultiplu(DestinatiBackup):
    """
    Trimite alertele catre mai multe destinatii simultan.
    Daca o destinatie esueaza, continua cu celelalte.
    Returneaza True daca cel putin o destinatie a reusit.

    Exemplu:
        backup = BackupMultiplu([
            BackupSyslogVM("192.168.1.100"),
            BackupFolderLocal("D:/backup/alerte.log"),
        ])
    """

    def __init__(self, destinatii: list):
        self.destinatii = destinatii

    def trimite(self, alerta: dict) -> bool:
        """Trimite catre toate destinatiile, returneaza True daca cel putin una reuseste."""
        rezultate = [dest.trimite(alerta) for dest in self.destinatii]
        return any(rezultate)

    def adauga_destinatie(self, destinatie: DestinatiBackup):
        """Adauga o noua destinatie la lista existenta."""
        self.destinatii.append(destinatie)



class BackupNoop(DestinatiBackup):
    """
    Destinatie de backup care nu face nimic.
    Folosita ca valoare implicita cand nu e configurata nicio destinatie.

    Pattern: Null Object — elimina nevoia de verificari 'if backup is not None'
    in restul codului. Codul apeleaza backup.trimite() indiferent de configuratie.
    """
    def trimite(self, alerta: dict) -> bool:
        return True   # simuleaza succes fara a face nimic
