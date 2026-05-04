"""ml_detector.py - Detectia anomaliilor cu Isolation Forest (atacuri necunoscute)"""
import time, os, threading
try:
    from sklearn.ensemble import IsolationForest
    import joblib
    ML_DISPONIBIL = True
except ImportError:
    ML_DISPONIBIL = False
    print("[ML] scikit-learn sau joblib nu sunt instalate. pip install scikit-learn joblib")

from detector import DetectorAtac
from backup import BackupNoop


class DetectorAnomalii(DetectorAtac):
    """
    Isolation Forest pentru detectia comportamentului anormal.
    Faza 1 (baseline): antreneaza modelul pe trafic normal.
    Faza 2 (detectie): prezice daca o fereastra de trafic e anomalie.

    Atribute noi fata de versiunea initiala:
        activ       - daca False, analizeaza() returneaza imediat (toggle din UI)
        db_override - DB alternativ folosit la antrenare (fisier extern)
    """
    NUME = "Anomalie ML"; SEVERITATE = "MEDIE"
    FEREASTRA_SECUNDE = 60
    CALE_MODEL = "hids_model.pkl"

    def __init__(self, db, backup=None, sursa="live", ip_gazda=None):
        super().__init__(db, backup, sursa, ip_gazda)
        self.model = None
        self.activ = False   # activat explicit din UI (AppState.toggle_detectie_ml)
        self._incarcare_model()

    def _incarcare_model(self):
        """Incarca modelul de pe disk daca exista."""
        if not ML_DISPONIBIL:
            return
        if os.path.exists(self.CALE_MODEL):
            try:
                self.model = joblib.load(self.CALE_MODEL)
                print(f"[ML] Model incarcat din {self.CALE_MODEL}")
            except Exception as e:
                print(f"[ML] Eroare incarcare model: {e}")

    def _extrage_features(self, ts_start, ts_end, db=None):
        """
        Calculeaza features agregate dintr-o fereastra de timp.
        Accepta un DB optional (pentru antrenare din fisier extern).
        """
        db = db or self.db
        f  = db.get_features_fereastra(ts_start, ts_end)
        if not f or f.get("total_pachete", 0) == 0:
            return None
        total = max(f["total_pachete"], 1)
        return [
            f["total_pachete"],
            f["total_bytes"],
            f["surse_unice"],
            f["destinatii_unice"],
            f["porturi_unice"],
            f["dim_medie"],
            f["cnt_tcp"] / total,
            f["cnt_udp"] / total,
            f["cnt_syn"] / total,
        ]

    def antreneaza_baseline(self, ore=48, progres_cb=None,
                             stop_cb=None, db_override=None):
        """
        Antreneaza modelul pe datele istorice din DB.

        Parametri noi:
            stop_cb     - callable() -> bool; daca returneaza True, opreste antrenarea
            db_override - instanta ManagerBazaDate alternativa (fisier extern)
        """
        if not ML_DISPONIBIL:
            print("[ML] scikit-learn nedisponibil, antrenarea nu e posibila.")
            return False

        db = db_override or self.db
        print(f"[ML] Inceput antrenare baseline pe {ore}h de date...")
        ts_end   = time.time()
        ts_start = ts_end - ore * 3600

        X = []
        t = ts_start
        total_ferestre = int(ore * 3600 / self.FEREASTRA_SECUNDE)
        procesate      = 0

        while t < ts_end:
            if stop_cb and stop_cb():
                print("[ML] Antrenare oprita de utilizator.")
                return False

            features = self._extrage_features(t, t + self.FEREASTRA_SECUNDE, db=db)
            if features:
                X.append(features)
            t         += self.FEREASTRA_SECUNDE
            procesate += 1
            if progres_cb:
                progres_cb(t, ts_end)

        print(f"[ML] Ferestre procesate: {procesate} | "
              f"Ferestre cu date: {len(X)} | "
              f"Minim necesar: 10")

        if len(X) < 10:
            print(f"[ML] Date insuficiente: {len(X)} ferestre cu trafic. "
                  "Colecteaza mai mult trafic si reincearca.")
            return False

        self.model = IsolationForest(contamination=0.05, random_state=42,
                                     n_estimators=100)
        self.model.fit(X)
        joblib.dump(self.model, self.CALE_MODEL)
        print(f"[ML] Model antrenat pe {len(X)} ferestre, "
              f"salvat in {self.CALE_MODEL}")
        return True

    def analizeaza(self, fereastra_secunde=60):
        """Analizeaza fereastra curenta si emite alerta daca e anomalie."""
        if not ML_DISPONIBIL or not self.model:
            return
        if not self.activ:      # detectia a fost dezactivata din UI
            return

        ts_end   = time.time()
        ts_start = ts_end - fereastra_secunde
        features = self._extrage_features(ts_start, ts_end)
        if not features:
            return

        predictie = self.model.predict([features])[0]
        scor      = abs(self.model.decision_function([features])[0])

        if predictie == -1:
            nume_features = ["total_pachete", "total_bytes", "surse_unice",
                             "destinatii_unice", "porturi_unice", "dim_medie",
                             "ratio_tcp", "ratio_udp", "ratio_syn"]
            idx_max         = features.index(max(features))
            feature_suspect = nume_features[idx_max]

            self.SEVERITATE = "RIDICATA" if scor > 0.3 else "MEDIE"
            self._emite_alerta(
                detalii=(f"Anomalie ML detectata (scor={scor:.3f}). "
                         f"Feature deviat: {feature_suspect}="
                         f"{features[idx_max]:.1f}. "
                         f"Verifica si confirma ca TP sau FP din sectiunea Alerte."))


class ColectorBaseline:
    """Colecteaza trafic normal si antreneaza modelul dupa N ore."""

    def __init__(self, detector_anomalii: DetectorAnomalii,
                 ore_necesare: int = 2):
        self.detector    = detector_anomalii
        self.ore_necesare = ore_necesare
        self._thread     = None

    def start_colectare_si_antrenare(self):
        self._thread = threading.Thread(
            target=self._colecteaza_si_antreneaza, daemon=True)
        self._thread.start()
        print(f"[ML] Colectare baseline pornita. "
              f"Antrenare dupa {self.ore_necesare}h.")

    def _colecteaza_si_antreneaza(self):
        print(f"[ML] Astept {self.ore_necesare}h pentru baseline...")
        time.sleep(self.ore_necesare * 3600)
        self.detector.antreneaza_baseline(ore=self.ore_necesare)