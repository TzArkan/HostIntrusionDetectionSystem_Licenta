"""
fim.py - Monitorizarea integritatii fisierelor (File Integrity Monitoring)
Responsabilitati:
  - Calculeaza hash SHA-256 al fisierelor monitorizate la pornire (baseline)
  - Verifica periodic daca hash-urile s-au schimbat
  - Emite alerte pentru fisiere modificate, sterse sau aparute
  - Ruleaza intr-un thread daemon, transparent fata de restul aplicatiei
"""

import hashlib
import os
import time
import threading
from backup import DestinatiBackup, BackupNoop


class MonitorIntegritateFisiere:
    """
    Compara periodic hash-urile SHA-256 ale fisierelor critice cu baseline-ul
    initial. Orice diferenta neautorizata genereaza o alerta in DB si backup.
    """

    INTERVAL_VERIFICARE = 300   # secunde intre verificari (implicit 5 minute)

    # Fisiere implicite monitorizate pe Windows
    # Pot fi extinse din interfata (SecțiuneSetari) sau din main.py
    FISIERE_IMPLICITE = [
        r"C:\Windows\System32\drivers\etc\hosts",
        r"C:\Windows\System32\drivers\etc\services",
        r"C:\Windows\System32\drivers\etc\networks",
    ]

    def __init__(self, db, backup: DestinatiBackup = None,
                 fisiere_suplimentare: list = None,
                 interval_secunde: int = None):
        """
        db                   - instanta ManagerBazaDate injectata din exterior
        backup               - destinatia de backup pentru alerte (optional)
        fisiere_suplimentare - lista de cai suplimentare de monitorizat
        interval_secunde     - suprascrie INTERVAL_VERIFICARE daca e specificat
        """
        self.db      = db
        self.backup  = backup or BackupNoop()
        self._activ  = False
        self._thread = None

        if interval_secunde:
            self.INTERVAL_VERIFICARE = interval_secunde

        # Combinam fisierele implicite cu cele din DB (Setari) si CLI
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
        """
        Calculeaza hash SHA-256 al unui fisier.

        Citeste fisierul in blocuri de 8192 bytes (8KB) pentru a evita
        incarcarea integrala in memorie a fisierelor mari.

        Returneaza hash-ul ca string hexazecimal (64 caractere),
        sau None daca fisierul nu poate fi citit (permisiuni, blocat etc.).
        """
        try:
            h = hashlib.sha256()
            with open(cale, "rb") as f:
                # iter(callable, sentinel) apeleaza callable() pana cand
                # returneaza valoarea sentinel (b"" = bloc gol = EOF)
                for bloc in iter(lambda: f.read(8192), b""):
                    h.update(bloc)   # actualizeaza hash-ul incremental
            return h.hexdigest()     # returneaza hash-ul final ca string hex
        except (OSError, PermissionError) as e:
            print(f"[FIM] Nu pot citi '{cale}': {e}")
            return None


    def _inregistreaza_in_baseline(self, cale: str):
        """
        Calculeaza hash-ul unui fisier si il salveaza in tabela fim_baseline.
        Daca intrarea exista deja, o actualizeaza (upsert).
        """
        hash_val = self.hash_fisier(cale)
        if hash_val:
            self.db.upsert_fim_baseline(cale, hash_val)
            print(f"[FIM] Baseline: {os.path.basename(cale)} -> {hash_val[:16]}...")

    def initializare_baseline(self):
        """
        Calculeaza si salveaza hash-urile initiale pentru toate fisierele.
        Se apeleaza o singura data la pornirea monitorului.

        Fisierele inexistente la momentul initierii sunt inregistrate
        in lista de asteptare — vor fi adaugate la baseline cand apar.
        """
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
        """
        Adauga un fisier nou la lista de monitorizare in timp real.
        Daca fisierul exista, ii calculeaza imediat hash-ul baseline.
        Poate fi apelata din interfata de setari.
        """
        if cale not in self.fisiere:
            self.fisiere.append(cale)
            if os.path.exists(cale):
                self._inregistreaza_in_baseline(cale)
                print(f"[FIM] Fisier adaugat la monitorizare: {cale}")

    def scoate_fisier(self, cale: str):
        """Elimina o cale din lista de monitorizare (nu sterge randul din baseline)."""
        if cale in self.fisiere:
            self.fisiere.remove(cale)
            print(f"[FIM] Scos din monitorizare: {cale}")


    def verifica_o_data(self):
        """
        Compara hash-urile curente ale tuturor fisierelor cu baseline-ul.
        Emite alerte pentru orice diferenta detectata.
        Apelata periodic de thread-ul intern sau manual pentru analiza pasiva.
        """
        # Incarcam baseline-ul din DB sub forma {cale: hash}
        baseline = {
            r["cale_fisier"]: r["hash_sha256"]
            for r in self.db.get_fim_baseline()
        }

        for cale in self.fisiere:
            if not os.path.exists(cale):
                # Fisierul nu mai exista — verificam daca era in baseline
                if cale in baseline:
                    self._emite_alerta("FISIER STERS sau MUTAT", cale)
                continue  # trecem la urmatorul fisier

            hash_curent = self.hash_fisier(cale)
            if hash_curent is None:
                continue  # nu putem citi fisierul, sarim

            if cale in baseline:
                if hash_curent != baseline[cale]:
                    # Hash diferit fata de baseline = fisier modificat
                    self._emite_alerta("FISIER MODIFICAT", cale,
                                       hash_vechi=baseline[cale],
                                       hash_nou=hash_curent)
                    # Actualizam baseline cu noul hash pentru a nu alerta repetat
                    self.db.upsert_fim_baseline(cale, hash_curent)
                else:
                    # Hash identic = fisier intact, actualizam doar timestamp-ul
                    self.db.update_fim_timestamp(cale)
            else:
                # Fisier nou aparut care nu era in baseline — il inregistram
                print(f"[FIM] Fisier nou detectat, adaugat la baseline: {cale}")
                self._inregistreaza_in_baseline(cale)


    def _emite_alerta(self, tip: str, cale: str,
                      hash_vechi: str = None, hash_nou: str = None):
        """
        Salveaza alerta FIM in DB si o trimite la backup.

        Parametri:
            tip       - tipul alertei: "FISIER MODIFICAT" sau "FISIER STERS sau MUTAT"
            cale      - calea completa a fisierului afectat
            hash_vechi - hash-ul din baseline (pentru fisiere modificate)
            hash_nou  - noul hash calculat (pentru fisiere modificate)
        """
        detalii = f"{tip}: {cale}"
        if hash_vechi and hash_nou:
            # Afisam primele 16 caractere din hash pentru lizibilitate
            detalii += f" | vechi={hash_vechi[:16]}... nou={hash_nou[:16]}..."

        alerta = {
            "tip_atac":   f"FIM - {tip}",
            "severitate": "CRITICA",
            "src_ip":     None,
            "dst_ip":     None,
            "detalii":    detalii,
            "timestamp":  time.time(),
        }

        # Salvare in DB
        self.db.inserare_alerta(
            tip_atac   = alerta["tip_atac"],
            severitate = alerta["severitate"],
            detalii    = alerta["detalii"],
            sursa      = "live",
        )

        # Trimitere catre backup (syslog / folder local)
        self.backup.trimite(alerta)

        print(f"[FIM] ALERTA [{tip}]: {os.path.basename(cale)}")


    def start(self):
        """
        Initializeaza baseline-ul si porneste verificarea periodica
        intr-un thread daemon (se opreste automat la inchiderea aplicatiei).
        """
        self.initializare_baseline()
        self._activ  = True
        self._thread = threading.Thread(target=self._bucla, daemon=False)
        self._thread.start()
        print(f"[FIM] Monitor pornit (verificare la {self.INTERVAL_VERIFICARE}s)")

    def stop(self):
        """Opreste bucla de verificare la urmatoarea iteratie."""
        self._activ = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        print("[FIM] Monitor oprit.")

    def _bucla(self):
        """
        Bucla interna a thread-ului.
        Asteapta INTERVAL_VERIFICARE secunde, apoi ruleaza o verificare completa.
        Verifica flag-ul _activ la fiecare secunda pentru oprire rapida.
        """
        while self._activ:
            # Asteptam intervalul configurabil, verificand periodic oprirea
            for _ in range(self.INTERVAL_VERIFICARE):
                if not self._activ:
                    return
                time.sleep(1)
            if self._activ:
                self.verifica_o_data()
