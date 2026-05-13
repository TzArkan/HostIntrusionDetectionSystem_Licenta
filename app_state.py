"""app_state.py - Starea globala partajata intre toate componentele."""
import os
import threading
import tempfile
import shutil
from db import ManagerBazaDate

_IMPORT_DIR = os.path.dirname(os.path.abspath(__file__))

ML_MODEL_PATH = "hids_model.pkl"


class AppState:
    """
    Contine referintele la DB si modul curent (live/pasiv).
    Gestioneaza si starea ML: antrenare, detectie activa/inactiva.
    """
    def __init__(self, db_live: ManagerBazaDate):
        self.db_live  = db_live
        self.db_pasiv = None
        self.mod      = "live"   # "live" sau "pasiv"

        # ── ML state ──────────────────────────────────────────────────────────
        self._ml_lock    = threading.Lock()
        self._ml_status  = "trained" if os.path.exists(ML_MODEL_PATH) else "ready"
        self._ml_stop    = False
        self._ml_thread  = None
        self.ml_msg      = ("✓ Model incarcat de pe disk."
                            if os.path.exists(ML_MODEL_PATH) else "")

        self.detectie_ml_activa = False
        self.detector_ml        = None

        # Setat de AnalistPachete dupa detectia interfetelor
        # Format: [{"name": "Wi-Fi", "ip": "192.168.1.x", "tip": "fizica"}, ...]
        self.interfete_active: list = []

        # Dict {iface_name: ManagerSesiuneInterfata} — setat din main.py
        self.manageri_interfete: dict = {}

        # Interfata selectata curent in dashboard (Trafic / Statistici)
        # None = toate interfetele combinate
        self.interfata_selectata: str = None

        # Timestamp pornire sesiune curente — folosit pentru filtrare alerte
        import time as _time
        self.sesiune_start: float = _time.time()

        # Referinta la MonitorIntegritateFisiere (setata din main.py) pentru adaugari din UI
        self.fim_monitor = None

        # Calea fisierului .db selectat la incarcare pasiva (pentru scan repetat)
        self._cale_pasiv_original: str | None = None
        self._pasiv_scan_tmp: str | None = None

    def get_manager_interfata(self, iface_name: str = None):
        """
        Returneaza managerul per-interfata pentru iface_name.
        Daca iface_name e None sau nu exista, returneaza None (foloseste DB principal).
        """
        if not iface_name or iface_name not in self.manageri_interfete:
            return None
        return self.manageri_interfete[iface_name]

    # ── DB activ ──────────────────────────────────────────────────────────────

    @property
    def db(self) -> ManagerBazaDate:
        """Returneaza DB-ul activ in functie de modul curent."""
        if self.mod == "pasiv" and self.db_pasiv:
            return self.db_pasiv
        return self.db_live

    def activeaza_mod_pasiv(self, cale_db: str) -> bool:
        try:
            if self._pasiv_scan_tmp and os.path.isfile(self._pasiv_scan_tmp):
                try:
                    os.unlink(self._pasiv_scan_tmp)
                except OSError:
                    pass
                self._pasiv_scan_tmp = None
            self.db_pasiv = ManagerBazaDate(cale_db, read_only=True)
            self.mod = "pasiv"
            self._cale_pasiv_original = os.path.abspath(cale_db)
            print(f"[STATE] Mod pasiv activ: {cale_db}")
            return True
        except Exception as e:
            print(f"[STATE] Eroare incarcare DB pasiv: {e}")
            return False

    def activeaza_mod_live(self):
        """Live foloseste db_live; pastram db_pasiv pentru revenire la Pasiv."""
        self.mod = "live"
        print("[STATE] Mod live activ")

    def enter_pasiv_mode(self):
        """UI Pasiv (fara a incarca neaparat un fisier nou)."""
        self.mod = "pasiv"

    def scan_reguli_pe_captura_pasiva(self, ip_gazda: str) -> tuple[bool, str]:
        """
        Copie RW a DB-ului pasiv, ruleaza detectorii built-in + reguli custom
        din db_live pe pachetele din captura (moment referinta = MAX(timestamp)).
        """
        from detector import ManagerDetectie
        from backup import BackupNoop
        from enrichment import EnrichmentService

        if not self._cale_pasiv_original or not os.path.isfile(
                self._cale_pasiv_original):
            return False, "Încarcă mai întâi un fișier .db în modul Pasiv."

        if self._pasiv_scan_tmp and os.path.isfile(self._pasiv_scan_tmp):
            try:
                os.unlink(self._pasiv_scan_tmp)
            except OSError:
                pass
            self._pasiv_scan_tmp = None

        fd, tmp = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            shutil.copy2(self._cale_pasiv_original, tmp)
        except OSError as e:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return False, f"Nu pot copia baza: {e}"

        self._pasiv_scan_tmp = tmp
        mdb = ManagerBazaDate(tmp, read_only=False)
        ref_ts = mdb.get_max_packet_timestamp()
        if ref_ts is None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            self._pasiv_scan_tmp = None
            return False, "Nu există pachete în captură."

        geo_dir = os.path.join(_IMPORT_DIR, "geoip")
        enrich = EnrichmentService(ip_gazda=ip_gazda, geoip_dir=geo_dir)
        mgr = ManagerDetectie(
            mdb,
            backup=BackupNoop(),
            sursa="pasiv_scan",
            ip_gazda=ip_gazda,
            enrichment=enrich,
            reguli_db=self.db_live,
        )
        try:
            mgr.ruleaza_o_data(reference_time=ref_ts)
        except Exception as e:
            print(f"[STATE] Eroare scan pasiv: {e}")
            try:
                os.unlink(tmp)
            except OSError:
                pass
            self._pasiv_scan_tmp = None
            return False, f"Eroare la scanare: {e}"

        self.db_pasiv = mdb
        self.mod = "pasiv"
        return True, "✓ Scan complet (reguli built-in + custom din DB live)."

    # ── ML status (thread-safe) ───────────────────────────────────────────────

    @property
    def ml_status(self) -> str:
        with self._ml_lock:
            return self._ml_status

    @ml_status.setter
    def ml_status(self, val: str):
        with self._ml_lock:
            self._ml_status = val

    # ── Utilitare ML ─────────────────────────────────────────────────────────

    def are_date(self) -> bool:
        """Verifica daca exista suficiente pachete in DB-ul live (minim 50)."""
        try:
            cur = self.db_live._get_conexiune().cursor()
            cur.execute("SELECT COUNT(*) AS c FROM packets")
            row = cur.fetchone()
            cur.close()
            return (row["c"] if row else 0) > 50
        except Exception:
            return False

    def are_date_suficiente_ml(self) -> tuple[bool, str]:
        """
        Verifica daca exista cel putin 1 ora de date captate in DB.
        Returneaza (ok: bool, mesaj: str).
        """
        try:
            cur = self.db_live._get_conexiune().cursor()
            cur.execute("""
                SELECT MIN(timestamp) AS ts_min,
                       MAX(timestamp) AS ts_max,
                       COUNT(*)       AS total
                FROM packets
            """)
            row = cur.fetchone()
            cur.close()
            if not row or not row["total"] or row["total"] < 50:
                return False, "Nicio data capturata inca."
            interval_ore = (row["ts_max"] - row["ts_min"]) / 3600.0
            if interval_ore < 1.0:
                return False, (f"Date disponibile: {interval_ore*60:.0f} minute. "
                               f"Sunt necesare cel putin 60 minute de trafic.")
            return True, f"Date disponibile: {interval_ore:.1f} ore."
        except Exception as e:
            return False, f"Eroare verificare date: {e}"

    # ── Antrenare ML ─────────────────────────────────────────────────────────

    def incepe_antrenare(self, ore: float = 24.0,
                          cale_db_extern: str = None) -> bool:
        """
        Porneste antrenarea modelului intr-un thread daemon.
        Returneaza False daca o antrenare e deja in curs.
        """
        if self.ml_status == "training":
            return False
        self._ml_stop  = False
        self.ml_status = "training"

        def _run():
            try:
                db_src = self.db_live
                if cale_db_extern:
                    db_src = ManagerBazaDate(cale_db_extern, read_only=True)
                if self.detector_ml:
                    ok = self.detector_ml.antreneaza_baseline(
                        ore         = ore,
                        db_override = db_src,
                        stop_cb     = lambda: self._ml_stop,
                    )
                    if ok and not self._ml_stop:
                        self.ml_status = "trained"
                        self.ml_msg    = (f"✓ Model antrenat si salvat "
                                          f"({ore}h de date).")
                    else:
                        self.ml_status = "ready"
                        self.ml_msg    = ("✗ Date insuficiente sau antrenare oprita. "
                                          "Colecteaza mai mult trafic si reincearca.")
                else:
                    self.ml_status = "ready"
                    self.ml_msg    = "✗ Eroare interna: detector ML nedisponibil."
            except Exception as e:
                print(f"[STATE] Eroare antrenare ML: {e}")
                self.ml_status = "ready"
                self.ml_msg    = f"✗ Eroare antrenare: {e}"

        self._ml_thread = threading.Thread(target=_run, daemon=True,
                                           name="ml-training")
        self._ml_thread.start()
        return True

    def opreste_antrenare(self):
        self._ml_stop  = True
        self.ml_status = "ready"
        self.ml_msg    = "✗ Antrenare oprita de utilizator."
        print("[STATE] Antrenare ML oprita de utilizator.")

    def sterge_model(self):
        """Sterge fisierul model de pe disk, reseteaza detectorul si dezactiveaza detectia."""
        try:
            if os.path.exists(ML_MODEL_PATH):
                os.remove(ML_MODEL_PATH)
                print(f"[STATE] Model ML sters: {ML_MODEL_PATH}")
        except Exception as e:
            print(f"[STATE] Nu pot sterge modelul: {e}")
        if self.detector_ml:
            self.detector_ml.model = None
            self.detector_ml.activ = False
        self.detectie_ml_activa = False
        self.ml_status = "ready"
        self.ml_msg    = "Model sters. Poti reantrena oricand."

    # ── Toggle detectie ML ────────────────────────────────────────────────────

    def toggle_detectie_ml(self) -> bool:
        """Activeaza/dezactiveaza detectia ML. Returneaza noua stare."""
        self.detectie_ml_activa = not self.detectie_ml_activa
        if self.detector_ml:
            self.detector_ml.activ = self.detectie_ml_activa
        stare = "ACTIVA" if self.detectie_ml_activa else "INACTIVA"
        print(f"[STATE] Detectie ML: {stare}")
        return self.detectie_ml_activa