import hashlib
import os
import time
import threading
from backup import DestinatiBackup, BackupNoop


class MonitorIntegritateFisiere:
    INTERVAL_VERIFICARE = 10 

    FISIERE_IMPLICITE = [
        r"C:\Windows\System32\drivers\etc\hosts",
        r"C:\Windows\System32\drivers\etc\services",
        r"C:\Windows\System32\drivers\etc\networks",
    ]

    def __init__(self, db, backup: DestinatiBackup = None,
                 fisiere_suplimentare: list = None,
                 interval_secunde: int = None):
        self.db      = db
        self.backup  = backup or BackupNoop()
        self._activ  = False
        self._thread = None

        if interval_secunde:
            self.INTERVAL_VERIFICARE = interval_secunde

        self.fisiere = list(self.FISIERE_IMPLICITE)
        try:
            for row in self.db.get_fim_cai_user():
                c = row["cale"]
                if c not in self.fisiere:
                    self.fisiere.append(c)
        except Exception as e:
            print(f"[FIM] Nu pot incarca cai din DB: {e}")
        if fisiere_suplimentare:
            for cale in fisiere_suplimentare:
                if cale not in self.fisiere:
                    self.fisiere.append(cale)


    @staticmethod
    def hash_fisier(cale: str) -> str | None:
        try:
            h = hashlib.sha256()
            with open(cale, "rb") as f:
                for bloc in iter(lambda: f.read(8192), b""):
                    h.update(bloc) 
            return h.hexdigest()     
        except (OSError, PermissionError) as e:
            print(f"[FIM] Nu pot citi '{cale}': {e}")
            return None


    def _inregistreaza_in_baseline(self, cale: str):
        hash_val = self.hash_fisier(cale)
        if hash_val:
            self.db.upsert_fim_baseline(cale, hash_val)
            print(f"[FIM] Baseline: {os.path.basename(cale)} -> {hash_val[:16]}...")

    def initializare_baseline(self):
        print(f"[FIM] Initializare baseline pentru {len(self.fisiere)} fisiere...")
        gasite = 0
        for cale in self.fisiere:
            if os.path.exists(cale):
                self._inregistreaza_in_baseline(cale)
                gasite += 1
            else:
                print(f"[FIM] Nu exista (va fi monitorizat la aparitie): {cale}")
        print(f"[FIM] Baseline initializat: {gasite}/{len(self.fisiere)} fisiere gasite.")

    def adauga_fisier(self, cale: str):
        if cale not in self.fisiere:
            self.fisiere.append(cale)
            if os.path.exists(cale):
                self._inregistreaza_in_baseline(cale)
                print(f"[FIM] Fisier adaugat la monitorizare: {cale}")

    def scoate_fisier(self, cale: str):
        if cale in self.fisiere:
            self.fisiere.remove(cale)
            print(f"[FIM] Scos din monitorizare: {cale}")


    def verifica_o_data(self):
        baseline = {
            r["cale_fisier"]: r["hash_sha256"]
            for r in self.db.get_fim_baseline()
        }

        for cale in list(self.fisiere):
            if not os.path.exists(cale):
                if cale in baseline:
                    self._emite_alerta("FISIER STERS sau MUTAT", cale)
                    self.scoate_fisier(cale)
                continue 

            hash_curent = self.hash_fisier(cale)
            if hash_curent is None:
                continue 

            if cale in baseline:
                if hash_curent != baseline[cale]:
                    self._emite_alerta("FISIER MODIFICAT", cale,
                                       hash_vechi=baseline[cale],
                                       hash_nou=hash_curent)
                    self.db.upsert_fim_baseline(cale, hash_curent)
                else:
                    self.db.update_fim_timestamp(cale)
            else:
                print(f"[FIM] Fisier nou detectat, adaugat la baseline: {cale}")
                self._inregistreaza_in_baseline(cale)


    def _emite_alerta(self, tip: str, cale: str, hash_vechi: str = None, hash_nou: str = None):
        detalii = f"{tip}: {cale}"
        if hash_vechi and hash_nou:
            detalii += f" | vechi={hash_vechi[:16]}... nou={hash_nou[:16]}..."

        alerta = {
            "tip_atac":   f"FIM - {tip}",
            "severitate": "CRITICA",
            "src_ip":     None,
            "dst_ip":     None,
            "detalii":    detalii,
            "timestamp":  time.time(),
        }

        self.db.inserare_alerta(
            tip_atac   = alerta["tip_atac"],
            severitate = alerta["severitate"],
            detalii    = alerta["detalii"],
            sursa      = "live",
        )

        self.backup.trimite(alerta)

        print(f"[FIM] ALERTA [{tip}]: {os.path.basename(cale)}")


    def start(self):
        self.initializare_baseline()
        self._activ  = True
        self._thread = threading.Thread(target=self._bucla, daemon=False)
        self._thread.start()
        print(f"[FIM] Monitor pornit (verificare la {self.INTERVAL_VERIFICARE}s)")

    def stop(self):
        self._activ = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        print("[FIM] Monitor oprit.")

    def _bucla(self):
        while self._activ:
            for _ in range(self.INTERVAL_VERIFICARE):
                if not self._activ:
                    return
                time.sleep(1)
            if self._activ:
                self.verifica_o_data()
