"""
db.py - Gestionarea bazei de date SQLite
Tabele: packets, alerte, reguli_detectie, fim_baseline, config_detectori
"""

import sqlite3
import threading
import os
import time
import json


# Valorile implicite pentru toti parametrii detectori built-in
# Format: (detector, param, valoare_implicita)
CONFIG_DETECTORI_DEFAULT = [
    # Port Scan
    ("Port Scan",          "prag",        20),
    ("Port Scan",          "fereastra",   60),
    # DDoS SYN Flood
    ("DDoS SYN Flood",     "prag_syn",   200),
    ("DDoS SYN Flood",     "prag_surse",   5),
    ("DDoS SYN Flood",     "fereastra",   60),
    # DoS SYN Flood
    ("DoS SYN Flood",      "prag_syn",   300),
    ("DoS SYN Flood",      "fereastra",   60),
    # Brute Force
    ("Brute Force",        "prag",        10),
    ("Brute Force",        "fereastra",   60),
    # DNS Amplification
    ("DNS Amplification",  "prag_ratio",  5.0),
    ("DNS Amplification",  "prag_volum",  50),
    ("DNS Amplification",  "fereastra",   60),
    # Data Exfiltration (beaconing — volum mare + ritm foarte periodic; exclude rafala)
    ("Data Exfiltration",  "prag_pachete", 4000),
    ("Data Exfiltration",  "prag_std",      0.07),
    ("Data Exfiltration",  "prag_bytes",    8388608),
    ("Data Exfiltration",  "prag_med_min",  14.0),
    ("Data Exfiltration",  "fereastra",     300),
    # ICMP Flood
    ("ICMP Flood",         "prag",       100),
    ("ICMP Flood",         "fereastra",   60),
    # Anomalie ML
    ("Anomalie ML",        "fereastra",   60),
]


class ManagerBazaDate:
    def __init__(self, nume_baza_date="trafic_retea.db", read_only=False):
        director_principal  = os.path.dirname(os.path.abspath(__file__))
        self.cale_baza_date = os.path.join(director_principal, nume_baza_date)
        self.read_only      = read_only
        self._local         = threading.local()

    def _get_conexiune(self):
        if not hasattr(self._local, "conexiune") or \
                self._local.conexiune is None:
            if self.read_only:
                uri = f"file:{self.cale_baza_date}?mode=ro"
                con = sqlite3.connect(uri, check_same_thread=False, uri=True)
            else:
                con = sqlite3.connect(self.cale_baza_date,
                                      check_same_thread=False)
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA synchronous=NORMAL")
            self._local.conexiune = con
        return self._local.conexiune

    # ─── INITIALIZARE ────────────────────────────────────────────────────────

    def initializare_baza_date(self):
        con = self._get_conexiune()
        cur = con.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  REAL    NOT NULL,
                src_ip     TEXT,
                dst_ip     TEXT,
                src_port   TEXT,
                dst_port   TEXT,
                protocol   TEXT,
                packet_len INTEGER,
                tcp_flags  TEXT
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_ts  ON packets(timestamp)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets(dst_ip)")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS alerte (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  REAL    NOT NULL,
                tip_atac   TEXT,
                severitate TEXT,
                src_ip     TEXT,
                dst_ip     TEXT,
                detalii    TEXT,
                sursa      TEXT    DEFAULT 'live',
                confirmat  INTEGER DEFAULT NULL,
                context_json TEXT,
                src_country  TEXT,
                dst_country  TEXT,
                src_asn      TEXT,
                dst_asn      TEXT,
                local_process TEXT,
                vazut       INTEGER DEFAULT 0
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerte_ts ON alerte(timestamp)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerte_src_country ON alerte(src_country)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerte_local_process ON alerte(local_process)")

        # Migrare coloane pentru baze create cu versiuni anterioare
        cur.execute("PRAGMA table_info(alerte)")
        cols = {r["name"] for r in cur.fetchall()}
        alter_map = {
            "context_json": "TEXT",
            "src_country": "TEXT",
            "dst_country": "TEXT",
            "src_asn": "TEXT",
            "dst_asn": "TEXT",
            "local_process": "TEXT",
            "vazut": "INTEGER DEFAULT 0",
        }
        for col, ctype in alter_map.items():
            if col not in cols:
                cur.execute(f"ALTER TABLE alerte ADD COLUMN {col} {ctype}")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS reguli_detectie (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                nume              TEXT    NOT NULL,
                protocol          TEXT    DEFAULT 'all',
                port_destinatie   TEXT,
                tcp_flags_contine TEXT,
                prag_count        INTEGER DEFAULT 10,
                fereastra_secunde INTEGER DEFAULT 60,
                severitate        TEXT    DEFAULT 'MEDIE',
                activa            INTEGER DEFAULT 1
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS fim_baseline (
                cale_fisier       TEXT PRIMARY KEY,
                hash_sha256       TEXT NOT NULL,
                ultima_verificare REAL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS config_detectori (
                detector TEXT NOT NULL,
                param    TEXT NOT NULL,
                valoare  REAL NOT NULL,
                PRIMARY KEY (detector, param)
            )
        """)

        # Inserare valori implicite (ignora daca exista deja)
        for detector, param, valoare in CONFIG_DETECTORI_DEFAULT:
            cur.execute("""
                INSERT OR IGNORE INTO config_detectori (detector, param, valoare)
                VALUES (?, ?, ?)
            """, (detector, param, valoare))

        cur.execute("""
            SELECT param, valoare FROM config_detectori WHERE detector='Data Exfiltration'
        """)
        ex = {r["param"]: float(r["valoare"]) for r in cur.fetchall()}

        def _migrate_exfil(rows: tuple):
            for param, val in rows:
                cur.execute("""
                    UPDATE config_detectori SET valoare=? WHERE detector=? AND param=?
                """, (val, "Data Exfiltration", param))

        migrat_exfil = False
        # Istoric lax (10 / 2.0 / 50000)
        if (ex.get("prag_pachete") == 10.0 and ex.get("prag_std") == 2.0
                and ex.get("prag_bytes") == 50000.0):
            _migrate_exfil((
                ("prag_pachete", 4000.0),
                ("prag_std", 0.07),
                ("prag_bytes", 8388608.0),
            ))
            migrat_exfil = True

        # Mijlociu (40 / 0.85 / 200000)
        elif ((ex.get("prag_std") == 0.85 and ex.get("prag_bytes") == 200000.0)
              and abs(ex.get("prag_pachete", -1.0) - 40.0) < 0.01):
            _migrate_exfil((
                ("prag_pachete", 4000.0),
                ("prag_std", 0.07),
                ("prag_bytes", 8388608.0),
            ))
            migrat_exfil = True

        cur.execute("""
            INSERT OR IGNORE INTO config_detectori (detector, param, valoare)
            VALUES ('Data Exfiltration', 'prag_med_min', ?)
        """, (14.0,))

        if migrat_exfil:
            print("[DB] Data Exfiltration: praguri mărite puternic + filtru anti-rafală (prag_med_min).")

        con.commit()
        cur.close()
        print(f"[DB] Baza de date initializata: {self.cale_baza_date}")

    def curata_sesiune(self):
        """Goleste pachetele capturate pentru sesiunea curenta (detectorii folosesc acest flux)."""
        if self.read_only:
            return
        con = self._get_conexiune()
        con.execute("DELETE FROM packets")
        con.commit()
        print("[DB] Tabel packets golit (sesiune noua).")

    # ─── PACHETE ─────────────────────────────────────────────────────────────

    def inserare_pachet(self, timestamp, src_ip, dst_ip, src_port, dst_port,
                        protocol, packet_len, tcp_flags=None):
        if self.read_only:
            return
        con = self._get_conexiune()
        cur = con.cursor()
        cur.execute("""
            INSERT INTO packets
                (timestamp,src_ip,dst_ip,src_port,dst_port,
                 protocol,packet_len,tcp_flags)
            VALUES (?,?,?,?,?,?,?,?)
        """, (timestamp, src_ip, dst_ip, src_port, dst_port,
              protocol, packet_len, tcp_flags))
        con.commit()
        cur.close()

    def get_pachete_recente(self, limit=200):
        cur = self._get_conexiune().cursor()
        cur.execute("""
            SELECT id,timestamp,src_ip,dst_ip,src_port,dst_port,
                   protocol,packet_len,tcp_flags
            FROM packets ORDER BY timestamp DESC LIMIT ?
        """, (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        return rows

    def get_pachete_filtrate(self, src_ip=None, dst_ip=None,
                             src_port=None, dst_port=None,
                             protocol=None, tcp_flags=None,
                             min_len=None, max_len=None,
                             ip_exclus=None, limit=500, min_id=None):
        """Interogare pachete cu filtre multiple optionale."""
        cond   = []
        params = []
        if src_ip and src_ip.strip():
            cond.append("src_ip LIKE ?");  params.append(f"%{src_ip.strip()}%")
        if dst_ip and dst_ip.strip():
            cond.append("dst_ip LIKE ?");  params.append(f"%{dst_ip.strip()}%")
        if src_port and src_port.strip():
            cond.append("src_port = ?");   params.append(src_port.strip())
        if dst_port and dst_port.strip():
            cond.append("dst_port = ?");   params.append(dst_port.strip())
        if protocol and protocol != "all":
            cond.append("protocol = ?");   params.append(protocol)
        if tcp_flags and tcp_flags != "all":
            cond.append("tcp_flags LIKE ?"); params.append(f"%{tcp_flags}%")
        if min_len is not None:
            cond.append("packet_len >= ?"); params.append(int(min_len))
        if max_len is not None:
            cond.append("packet_len <= ?"); params.append(int(max_len))
        if ip_exclus:
            cond.append("src_ip != ?"); params.append(ip_exclus)
            cond.append("dst_ip != ?"); params.append(ip_exclus)
        if min_id is not None:
            cond.append("id > ?"); params.append(int(min_id))
        where = ("WHERE " + " AND ".join(cond)) if cond else ""
        params.append(limit)
        cur = self._get_conexiune().cursor()
        cur.execute(f"""
            SELECT id,timestamp,src_ip,dst_ip,src_port,dst_port,
                   protocol,packet_len,tcp_flags
            FROM packets {where} ORDER BY timestamp DESC LIMIT ?
        """, params)
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        return rows

    def get_ip_uri_unice(self, limit=200, ip_exclus=None):
        cur = self._get_conexiune().cursor()
        if ip_exclus:
            cur.execute("""
                SELECT DISTINCT src_ip AS ip FROM packets
                WHERE src_ip IS NOT NULL AND src_ip != ?
                UNION
                SELECT DISTINCT dst_ip AS ip FROM packets
                WHERE dst_ip IS NOT NULL AND dst_ip != ?
                ORDER BY ip LIMIT ?
            """, (ip_exclus, ip_exclus, limit))
        else:
            cur.execute("""
                SELECT DISTINCT src_ip AS ip FROM packets
                WHERE src_ip IS NOT NULL
                UNION
                SELECT DISTINCT dst_ip AS ip FROM packets
                WHERE dst_ip IS NOT NULL
                ORDER BY ip LIMIT ?
            """, (limit,))
        rows = [r["ip"] for r in cur.fetchall()]
        cur.close()
        return rows

    def get_pachete_intre_ip(self, ip1, ip2, interval_secunde=None,
                             src_port=None, dst_port=None, limit=500):
        cond   = ["((src_ip=? AND dst_ip=?) OR (src_ip=? AND dst_ip=?))"]
        params = [ip1, ip2, ip2, ip1]
        if interval_secunde:
            cond.append("timestamp >= ?")
            params.append(time.time() - interval_secunde)
        if src_port and src_port.strip():
            cond.append("src_port = ?"); params.append(src_port.strip())
        if dst_port and dst_port.strip():
            cond.append("dst_port = ?"); params.append(dst_port.strip())
        params.append(limit)
        cur = self._get_conexiune().cursor()
        cur.execute(f"""
            SELECT * FROM packets
            WHERE {' AND '.join(cond)}
            ORDER BY timestamp DESC LIMIT ?
        """, params)
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        return rows

    def get_statistici_ip(self, limit=100, ip_exclus=None):
        ec1 = f"AND src_ip != '{ip_exclus}'" if ip_exclus else ""
        ec2 = f"AND dst_ip != '{ip_exclus}'" if ip_exclus else ""
        cur = self._get_conexiune().cursor()
        cur.execute(f"""
            SELECT ip,
                   SUM(pkt_out) AS pachete_trimise,
                   SUM(pkt_in)  AS pachete_primite,
                   SUM(pkt_out)+SUM(pkt_in) AS pachete_total,
                   ROUND(SUM(bytes_out)/1048576.0,3) AS mb_trimisi,
                   ROUND(SUM(bytes_in) /1048576.0,3) AS mb_primiti,
                   ROUND((SUM(bytes_out)+SUM(bytes_in))*1.0
                         /NULLIF(SUM(pkt_out)+SUM(pkt_in),0),1) AS medie_bytes_pachet
            FROM (
                SELECT src_ip AS ip, COUNT(*) AS pkt_out, 0 AS pkt_in,
                       SUM(packet_len) AS bytes_out, 0 AS bytes_in
                FROM packets WHERE src_ip IS NOT NULL {ec1} GROUP BY src_ip
                UNION ALL
                SELECT dst_ip AS ip, 0 AS pkt_out, COUNT(*) AS pkt_in,
                       0 AS bytes_out, SUM(packet_len) AS bytes_in
                FROM packets WHERE dst_ip IS NOT NULL {ec2} GROUP BY dst_ip
            )
            GROUP BY ip ORDER BY pachete_total DESC LIMIT ?
        """, (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        return rows

    def get_porturi_scanate(self, src_ip, ts_start, ts_end):
        cur = self._get_conexiune().cursor()
        cur.execute("""
            SELECT dst_ip, dst_port, COUNT(*) AS tentative,
                   MIN(timestamp) AS prima_ora, MAX(timestamp) AS ultima_ora
            FROM packets
            WHERE src_ip=? AND timestamp BETWEEN ? AND ?
              AND protocol='TCP' AND tcp_flags LIKE '%S%' AND dst_port!='-'
            GROUP BY dst_ip, dst_port ORDER BY tentative DESC LIMIT 200
        """, (src_ip, ts_start - 120, ts_end + 120))
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        return rows

    def get_tentative_autentificare(self, src_ip, dst_ip, ts_start, ts_end):
        cur = self._get_conexiune().cursor()
        cur.execute("""
            SELECT timestamp, dst_port, tcp_flags, packet_len
            FROM packets
            WHERE src_ip=? AND dst_ip=?
              AND timestamp BETWEEN ? AND ?
              AND protocol='TCP'
            ORDER BY timestamp ASC LIMIT 500
        """, (src_ip, dst_ip, ts_start - 120, ts_end + 120))
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        return rows

    # ─── STATISTICI GRAFICE ───────────────────────────────────────────────────

    def get_statistici_alerte(self):
        cur = self._get_conexiune().cursor()
        cur.execute("""
            SELECT COUNT(*) AS total,
                   COALESCE(SUM(CASE WHEN confirmat IS NULL    THEN 1 ELSE 0 END), 0) AS in_asteptare,
                   COALESCE(SUM(CASE WHEN confirmat=1          THEN 1 ELSE 0 END), 0) AS true_positive,
                   COALESCE(SUM(CASE WHEN confirmat=0          THEN 1 ELSE 0 END), 0) AS false_positive,
                   COALESCE(SUM(CASE WHEN severitate='CRITICA' THEN 1 ELSE 0 END), 0) AS critica,
                   COALESCE(SUM(CASE WHEN severitate='RIDICATA' THEN 1 ELSE 0 END), 0) AS ridicata,
                   COALESCE(SUM(CASE WHEN severitate='MEDIE'   THEN 1 ELSE 0 END), 0) AS medie,
                   COALESCE(SUM(CASE WHEN severitate='SCAZUTA' THEN 1 ELSE 0 END), 0) AS scazuta
            FROM alerte
        """)
        row = cur.fetchone()
        cur.close()
        return dict(row) if row else {}

    def get_avg_pachete_per_secunda(self, interval_secunde=60):
        ts_start = time.time() - interval_secunde
        cur = self._get_conexiune().cursor()
        cur.execute("SELECT COUNT(*) AS total FROM packets WHERE timestamp >= ?",
                    (ts_start,))
        row = cur.fetchone()
        cur.close()
        if not row or not row["total"]:
            return 0.0
        return round(row["total"] / interval_secunde, 2)

    def get_pachete_per_secunda_per_ip(self, interval_secunde=300,
                                        bucket_secunde=10,
                                        ip_exclus=None):
        ts = time.time() - interval_secunde
        ec = f"AND src_ip != '{ip_exclus}'" if ip_exclus else ""
        cur = self._get_conexiune().cursor()
        cur.execute(f"""
            SELECT CAST((timestamp-{ts})/{bucket_secunde} AS INTEGER)
                   *{bucket_secunde}+{ts} AS ts_bucket,
                   src_ip, COUNT(*) AS cnt
            FROM packets
            WHERE timestamp>={ts} AND src_ip IS NOT NULL {ec}
            GROUP BY ts_bucket, src_ip
            ORDER BY ts_bucket, cnt DESC
        """)
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        return rows

    def get_distributie_protocol_timp(self, interval_secunde=300,
                                       bucket_secunde=10):
        ts = time.time() - interval_secunde
        cur = self._get_conexiune().cursor()
        cur.execute(f"""
            SELECT CAST((timestamp-{ts})/{bucket_secunde} AS INTEGER)
                   *{bucket_secunde}+{ts} AS ts_bucket,
                   protocol, COUNT(*) AS cnt
            FROM packets
            WHERE timestamp>={ts} AND protocol IS NOT NULL
            GROUP BY ts_bucket, protocol ORDER BY ts_bucket
        """)
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        return rows

    # ─── ALERTE ──────────────────────────────────────────────────────────────

    def inserare_alerta(self, tip_atac, severitate, src_ip=None,
                        dst_ip=None, detalii="", sursa="live", context=None):
        if self.read_only:
            return
        context = context or {}
        context_json = None
        try:
            context_json = json.dumps(context, ensure_ascii=True)
        except Exception:
            context_json = None
        src_geo = context.get("src_geo") or {}
        dst_geo = context.get("dst_geo") or {}
        proc = context.get("local_process") or {}
        con = self._get_conexiune()
        cur = con.cursor()
        cur.execute("""
            INSERT INTO alerte
                (timestamp,tip_atac,severitate,src_ip,dst_ip,detalii,sursa,
                 context_json,src_country,dst_country,src_asn,dst_asn,local_process)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            time.time(), tip_atac, severitate, src_ip, dst_ip, detalii, sursa,
            context_json,
            src_geo.get("country"),
            dst_geo.get("country"),
            str(src_geo.get("asn")) if src_geo.get("asn") is not None else None,
            str(dst_geo.get("asn")) if dst_geo.get("asn") is not None else None,
            proc.get("name"),
        ))
        con.commit()
        cur.close()

    def get_alerte(self, limit=200, ts_start=None, severitate=None,
                   tip_atac=None, confirmat_filter=None, ip_filter=None,
                   country_filter=None, asn_org_filter=None,
                   process_filter=None, external_only=False,
                   vazut_filter=None):
        cond   = []
        params = []
        if ts_start:
            cond.append("timestamp >= ?"); params.append(ts_start)
        if severitate and severitate != "all":
            cond.append("severitate = ?"); params.append(severitate)
        if tip_atac and tip_atac != "all":
            cond.append("tip_atac = ?");   params.append(tip_atac)
        if confirmat_filter == "asteptare":
            cond.append("confirmat IS NULL")
        elif confirmat_filter == "tp":
            cond.append("confirmat = 1")
        elif confirmat_filter == "fp":
            cond.append("confirmat = 0")
        if ip_filter and ip_filter.strip():
            cond.append("(src_ip LIKE ? OR dst_ip LIKE ?)")
            params.append(f"%{ip_filter.strip()}%")
            params.append(f"%{ip_filter.strip()}%")
        if country_filter and country_filter != "all":
            cond.append("(src_country = ? OR dst_country = ?)")
            params.append(country_filter)
            params.append(country_filter)
        if process_filter and process_filter.strip():
            cond.append("local_process LIKE ?")
            params.append(f"%{process_filter.strip()}%")
        if asn_org_filter and asn_org_filter.strip():
            cond.append("""
                (
                  src_asn LIKE ? OR dst_asn LIKE ?
                  OR COALESCE(context_json, '') LIKE ?
                )
            """)
            like = f"%{asn_org_filter.strip()}%"
            params.extend([like, like, like])
        if external_only:
            cond.append("(src_country IS NOT NULL OR dst_country IS NOT NULL)")
        if vazut_filter == "vazute":
            cond.append("COALESCE(vazut, 0) = 1")
        elif vazut_filter == "nevazute":
            cond.append("COALESCE(vazut, 0) = 0")
        where = ("WHERE " + " AND ".join(cond)) if cond else ""
        params.append(limit)
        cur = self._get_conexiune().cursor()
        cur.execute(f"""
            SELECT id,timestamp,tip_atac,severitate,src_ip,dst_ip,
                   detalii,sursa,confirmat,context_json,
                   src_country,dst_country,src_asn,dst_asn,local_process,vazut
            FROM alerte {where} ORDER BY timestamp DESC LIMIT ?
        """, params)
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            raw = r.get("context_json")
            if raw:
                try:
                    r["context"] = json.loads(raw)
                except Exception:
                    r["context"] = {}
            else:
                r["context"] = {}
        cur.close()
        return rows

    def get_alerta_by_id(self, alerta_id):
        cur = self._get_conexiune().cursor()
        cur.execute("""
            SELECT id,timestamp,tip_atac,severitate,src_ip,dst_ip,
                   detalii,sursa,confirmat,context_json,
                   src_country,dst_country,src_asn,dst_asn,local_process,vazut
            FROM alerte WHERE id=?
        """, (alerta_id,))
        row = cur.fetchone()
        cur.close()
        if not row:
            return None
        data = dict(row)
        raw = data.get("context_json")
        if raw:
            try:
                data["context"] = json.loads(raw)
            except Exception:
                data["context"] = {}
        else:
            data["context"] = {}
        return data

    def get_tari_alerte(self, limit=100):
        cur = self._get_conexiune().cursor()
        cur.execute("""
            SELECT country FROM (
                SELECT src_country AS country FROM alerte
                UNION ALL
                SELECT dst_country AS country FROM alerte
            )
            WHERE country IS NOT NULL AND TRIM(country) != ''
            GROUP BY country
            ORDER BY country
            LIMIT ?
        """, (limit,))
        rows = [r["country"] for r in cur.fetchall()]
        cur.close()
        return rows

    def update_confirmare_alerta(self, alerta_id, valoare):
        if self.read_only:
            return
        con = self._get_conexiune()
        cur = con.cursor()
        cur.execute("UPDATE alerte SET confirmat=? WHERE id=?",
                    (valoare, alerta_id))
        con.commit()
        cur.close()

    def update_vazut_alerta(self, alerta_id, vazut):
        if self.read_only:
            return
        con = self._get_conexiune()
        cur = con.cursor()
        cur.execute("UPDATE alerte SET vazut=? WHERE id=?",
                    (1 if vazut else 0, alerta_id))
        con.commit()
        cur.close()

    def count_alerte(self, ts_start=None, vazut=None):
        cond = []
        params = []
        if ts_start is not None:
            cond.append("timestamp >= ?")
            params.append(ts_start)
        if vazut is not None:
            cond.append("COALESCE(vazut, 0) = ?")
            params.append(1 if vazut else 0)
        where = ("WHERE " + " AND ".join(cond)) if cond else ""
        cur = self._get_conexiune().cursor()
        cur.execute(f"SELECT COUNT(*) AS c FROM alerte {where}", params)
        row = cur.fetchone()
        cur.close()
        return int(row["c"]) if row else 0

    # ─── REGULI DETECTIE ─────────────────────────────────────────────────────

    def inserare_regula(self, nume, protocol="all", port_destinatie=None,
                        tcp_flags_contine=None, prag_count=10,
                        fereastra_secunde=60, severitate="MEDIE"):
        if self.read_only:
            return
        con = self._get_conexiune()
        cur = con.cursor()
        cur.execute("""
            INSERT INTO reguli_detectie
                (nume,protocol,port_destinatie,tcp_flags_contine,
                 prag_count,fereastra_secunde,severitate,activa)
            VALUES (?,?,?,?,?,?,?,1)
        """, (nume, protocol, port_destinatie, tcp_flags_contine,
              prag_count, fereastra_secunde, severitate))
        con.commit()
        cur.close()

    def update_regula(self, regula_id, protocol=None, port_destinatie=None,
                      tcp_flags_contine=None, prag_count=None,
                      fereastra_secunde=None, severitate=None, activa=None):
        if self.read_only:
            return
        setari = []; params = []
        if protocol          is not None: setari.append("protocol=?");          params.append(protocol)
        if port_destinatie   is not None: setari.append("port_destinatie=?");   params.append(port_destinatie or None)
        if tcp_flags_contine is not None: setari.append("tcp_flags_contine=?"); params.append(tcp_flags_contine or None)
        if prag_count        is not None: setari.append("prag_count=?");        params.append(int(prag_count))
        if fereastra_secunde is not None: setari.append("fereastra_secunde=?"); params.append(int(fereastra_secunde))
        if severitate        is not None: setari.append("severitate=?");        params.append(severitate)
        if activa            is not None: setari.append("activa=?");            params.append(1 if activa else 0)
        if not setari:
            return
        params.append(regula_id)
        con = self._get_conexiune()
        cur = con.cursor()
        cur.execute(f"UPDATE reguli_detectie SET {','.join(setari)} WHERE id=?",
                    params)
        con.commit()
        cur.close()

    def sterge_regula(self, regula_id):
        if self.read_only:
            return
        con = self._get_conexiune()
        cur = con.cursor()
        cur.execute("DELETE FROM reguli_detectie WHERE id=?", (regula_id,))
        con.commit()
        cur.close()

    def get_toate_regulile(self):
        cur = self._get_conexiune().cursor()
        cur.execute("SELECT * FROM reguli_detectie ORDER BY id DESC")
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        return rows

    def get_reguli_active(self):
        cur = self._get_conexiune().cursor()
        cur.execute("SELECT * FROM reguli_detectie WHERE activa=1")
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        return rows

    # ─── CONFIG DETECTORI ────────────────────────────────────────────────────

    def get_config_detectori(self):
        """Returneaza toti parametrii tuturor detectori."""
        cur = self._get_conexiune().cursor()
        cur.execute("""
            SELECT detector, param, valoare
            FROM config_detectori
            ORDER BY detector, param
        """)
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        return rows

    def get_config_detector(self, detector: str, param: str,
                             default: float = 0) -> float:
        """
        Returneaza valoarea unui parametru specific pentru un detector.
        Folosit de detectori la fiecare rulare.
        """
        cur = self._get_conexiune().cursor()
        cur.execute("""
            SELECT valoare FROM config_detectori
            WHERE detector=? AND param=?
        """, (detector, param))
        row = cur.fetchone()
        cur.close()
        return float(row["valoare"]) if row else default

    def update_config_detector(self, detector: str, param: str,
                                valoare: float):
        """Actualizeaza sau insereaza un parametru (upsert)."""
        if self.read_only:
            return
        con = self._get_conexiune()
        cur = con.cursor()
        cur.execute("""
            INSERT INTO config_detectori (detector, param, valoare)
            VALUES (?, ?, ?)
            ON CONFLICT(detector, param) DO UPDATE SET valoare=excluded.valoare
        """, (detector, param, valoare))
        con.commit()
        cur.close()

    # ─── FIM BASELINE ────────────────────────────────────────────────────────

    def upsert_fim_baseline(self, cale_fisier, hash_sha256):
        if self.read_only:
            return
        con = self._get_conexiune()
        cur = con.cursor()
        cur.execute("""
            INSERT INTO fim_baseline (cale_fisier,hash_sha256,ultima_verificare)
            VALUES (?,?,?)
            ON CONFLICT(cale_fisier) DO UPDATE SET
                hash_sha256=excluded.hash_sha256,
                ultima_verificare=excluded.ultima_verificare
        """, (cale_fisier, hash_sha256, time.time()))
        con.commit()
        cur.close()

    def get_fim_baseline(self):
        cur = self._get_conexiune().cursor()
        cur.execute("SELECT cale_fisier,hash_sha256 FROM fim_baseline")
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        return rows

    def update_fim_timestamp(self, cale_fisier):
        if self.read_only:
            return
        con = self._get_conexiune()
        cur = con.cursor()
        cur.execute(
            "UPDATE fim_baseline SET ultima_verificare=? WHERE cale_fisier=?",
            (time.time(), cale_fisier))
        con.commit()
        cur.close()

    # ─── ML FEATURES ─────────────────────────────────────────────────────────

    def get_features_fereastra(self, ts_start, ts_end):
        cur = self._get_conexiune().cursor()
        cur.execute("""
            SELECT COUNT(*) AS total_pachete,
                   COALESCE(SUM(packet_len),0) AS total_bytes,
                   COUNT(DISTINCT src_ip)      AS surse_unice,
                   COUNT(DISTINCT dst_ip)      AS destinatii_unice,
                   COUNT(DISTINCT dst_port)    AS porturi_unice,
                   COALESCE(AVG(packet_len),0) AS dim_medie,
                   COUNT(CASE WHEN protocol='TCP'       THEN 1 END) AS cnt_tcp,
                   COUNT(CASE WHEN protocol='UDP'       THEN 1 END) AS cnt_udp,
                   COUNT(CASE WHEN tcp_flags LIKE '%S%' THEN 1 END) AS cnt_syn
            FROM packets WHERE timestamp>=? AND timestamp<?
        """, (ts_start, ts_end))
        row = cur.fetchone()
        cur.close()
        return dict(row) if row else None