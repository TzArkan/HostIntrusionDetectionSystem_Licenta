import os
import sys, time, threading, traceback, webbrowser, ctypes

from db          import ManagerBazaDate
from db_interfata import ManagerSesiuneInterfata
from capture     import AnalistPachete
from detector    import ManagerDetectie
from ml_detector import DetectorAnomalii
from dashboard_utils import get_ip_gazda
from fim         import MonitorIntegritateFisiere
from backup      import BackupMultiplu, BackupSyslogVM, BackupFolderLocal, BackupNoop
from dashboard   import DashboardRetea
from app_state   import AppState
from enrichment  import EnrichmentService


class AplicatieMonitorRetea:
    HOST = "127.0.0.1"; PORT = 8050

    SYSLOG_HOST   = "192.168.1.100"
    SYSLOG_PORT   = 514
    SYSLOG_ACTIV  = False
    BACKUP_FOLDER = None

    def __init__(self):
        self.db_manager  = ManagerBazaDate()
        self.state       = AppState(db_live=self.db_manager)
        self.backup      = self._configureaza_backup()
        self.ip_gazda    = get_ip_gazda()
        self.enrichment  = EnrichmentService(
            ip_gazda=self.ip_gazda,
            geoip_dir=os.path.join(os.path.dirname(os.path.abspath(__file__)), "geoip"),
        )
        print(f"[MAIN] IP gazda: {self.ip_gazda}")

        self.analist = AnalistPachete(
            manager_baza_date=self.db_manager,
            app_state=self.state)
        self._capture_thread = None

        self.detector = ManagerDetectie(
            db=self.db_manager,
            backup=self.backup,
            ip_gazda=self.ip_gazda,
            enrichment=self.enrichment)

        self.fim = MonitorIntegritateFisiere(
            db=self.db_manager,
            backup=self.backup)
        self.state.fim_monitor = self.fim

        self.detector_ml = DetectorAnomalii(
            db=self.db_manager,
            backup=self.backup,
            ip_gazda=self.ip_gazda)

        self.state.detector_ml = self.detector_ml
        self.detector.adauga_detector(self.detector_ml)
        self.dashboard = DashboardRetea(app_state=self.state)

    def _creeaza_manageri_interfete(self):
        """Creeaza un ManagerSesiuneInterfata pentru fiecare interfata activa."""
        folder = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "hids_data")
        for iface in self.state.interfete_active:
            name = iface.get("name", "")
            if not name or name in self.state.manageri_interfete:
                continue
            mgr = ManagerSesiuneInterfata(interfata=name, folder_baza=folder)
            mgr.curata_sesiune()
            self.state.manageri_interfete[name] = mgr
            print(f"[MAIN] Manager interfata: {name}")
        if self.state.manageri_interfete:
            # Seteaza prima interfata ca selectata implicit
            first = next(iter(self.state.manageri_interfete))
            self.state.interfata_selectata = first

    def _configureaza_backup(self):
        destinatii = []
        if self.SYSLOG_ACTIV:
            destinatii.append(BackupSyslogVM(self.SYSLOG_HOST, self.SYSLOG_PORT))
            print(f"[BACKUP] Syslog VM: {self.SYSLOG_HOST}:{self.SYSLOG_PORT}")
        if self.BACKUP_FOLDER:
            destinatii.append(BackupFolderLocal(self.BACKUP_FOLDER))
            print(f"[BACKUP] Folder local: {self.BACKUP_FOLDER}")
        return BackupMultiplu(destinatii) if destinatii else BackupNoop()

    def _este_admin(self):
        try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except: return True

    def ruleaza(self):
        print("=" * 50)
        print("   HIDS - Monitor Retea & Detectie Intruziuni")
        print("=" * 50)

        if not self._este_admin():
            print("[!] EROARE: Necesita drepturi de Administrator.")
            sys.exit(1)

        try:
            print("[*] Initializare baza de date...")
            self.db_manager.initializare_baza_date()
            self.db_manager.curata_sesiune()

            print("[*] Pornire captura pachete...")
            self._capture_thread = threading.Thread(
                target=self.analist.start_captura_pachete,
                daemon=False,
                name="capture-main")
            self._capture_thread.start()

            # Asteptam detectia interfetelor (max 2s)
            for _ in range(20):
                if self.state.interfete_active:
                    break
                time.sleep(0.1)
            self._creeaza_manageri_interfete()

            print("[*] Pornire detectori atacuri...")
            self.detector.start()

            print("[*] Pornire monitor integritate fisiere...")
            self.fim.start()

            threading.Thread(target=lambda: (
                time.sleep(2.5),
                webbrowser.open(f"http://{self.HOST}:{self.PORT}")
            ), daemon=True).start()

            print(f"[*] Dashboard: http://{self.HOST}:{self.PORT}")
            self.dashboard.start(debug=False)

        except KeyboardInterrupt:
            print("\n[*] Oprire solicitata...")
        except Exception as e:
            print(f"\n[!] Eroare critica: {e}")
            traceback.print_exc()
        finally:
            self.analist.stop()
            self.detector.stop()
            self.fim.stop()
            if self._capture_thread and self._capture_thread.is_alive():
                self._capture_thread.join(timeout=3)
            print("[*] Aplicatie inchisa.")


if __name__ == "__main__":
    AplicatieMonitorRetea().ruleaza()