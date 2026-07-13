import os
import re
import sqlite3
import time
import threading
import datetime


_SCHEMA_PACKETS = """
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
    );
    CREATE INDEX IF NOT EXISTS idx_ts  ON packets(timestamp);
    CREATE INDEX IF NOT EXISTS idx_src ON packets(src_ip);
    CREATE INDEX IF NOT EXISTS idx_dst ON packets(dst_ip);
"""

_DIMENSIUNE_CALUP = 200
_TIMP_CALUP   = 500


def sanitize_iface_name(name: str) -> str:
    safe = re.sub(r"[^\w]", "_", name).strip("_")
    return safe[:64] if safe else "unknown"


class ManagerSesiuneInterfata:
    def __init__(self, interfata: str, folder_baza: str = "hids_data"):
        self.interfata   = interfata
        self.iface_safe  = sanitize_iface_name(interfata)
        self.folder      = os.path.join(folder_baza, self.iface_safe)
        self.folder_arh  = os.path.join(self.folder, "sesiuni_anterioare")
        os.makedirs(self.folder,     exist_ok=True)
        os.makedirs(self.folder_arh, exist_ok=True)

        self.cale_sesiune = os.path.join(self.folder, "sesiune_curenta.db")
        self._lock        = threading.Lock()
        self._con         = None
        self._contor     = 0
        self._ultimul_commit = time.time()
        self._initializeaza()

    def _get_con(self) -> sqlite3.Connection:
        if self._con is None:
            self._con = sqlite3.connect(
                self.cale_sesiune, check_same_thread=False)
            self._con.row_factory = sqlite3.Row
            self._con.execute("PRAGMA journal_mode=WAL")
            self._con.execute("PRAGMA synchronous=NORMAL")
        return self._con

    def _initializeaza(self):
        con = self._get_con()
        con.executescript(_SCHEMA_PACKETS)
        con.commit()


    def _arhiveaza_sesiune(self):
        con = self._get_con()
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) AS n FROM packets")
        n = cur.fetchone()["n"]
        cur.close()
        if n == 0:
            return

        azi    = datetime.date.today().strftime("%Y_%m_%d")
        cale_a = os.path.join(self.folder_arh, f"{azi}.db")
        con_a  = sqlite3.connect(cale_a)
        con_a.execute("PRAGMA journal_mode=WAL")
        con_a.executescript(_SCHEMA_PACKETS)
        con_a.commit()

        cur = con.cursor()
        cur.execute("""
            SELECT timestamp,src_ip,dst_ip,src_port,dst_port,
                   protocol,packet_len,tcp_flags
            FROM packets ORDER BY timestamp
        """)
        rows = cur.fetchall()
        cur.close()
        con_a.executemany("""
            INSERT INTO packets
              (timestamp,src_ip,dst_ip,src_port,dst_port,
               protocol,packet_len,tcp_flags)
            VALUES (?,?,?,?,?,?,?,?)
        """, [tuple(r) for r in rows])
        con_a.commit()
        con_a.close()
        print(f"[DB-{self.iface_safe}] Arhivat {n} pachete -> {azi}.db")

    def curata_sesiune(self):
        with self._lock:
            self._arhiveaza_sesiune()
            self._get_con().execute("DELETE FROM packets")
            self._get_con().commit()
            self._contor     = 0
            self._ultimul_commit = time.time()
        print(f"[DB-{self.iface_safe}] Sesiune curatata.")


    def inserare_pachet(self, timestamp, src_ip, dst_ip,
                        src_port, dst_port, protocol,
                        packet_len, tcp_flags=None):
        with self._lock:
            self._get_con().execute("""
                INSERT INTO packets
                  (timestamp,src_ip,dst_ip,src_port,dst_port,
                   protocol,packet_len,tcp_flags)
                VALUES (?,?,?,?,?,?,?,?)
            """, (timestamp, src_ip, dst_ip, src_port, dst_port,
                  protocol, packet_len, tcp_flags))
            self._contor += 1
            now = time.time()
            if (self._contor >= _DIMENSIUNE_CALUP or
                 (now - self._ultimul_commit) * 1000 >= _TIMP_CALUP):
                self._get_con().commit()
                self._contor     = 0
                self._ultimul_commit = now

    def flush(self):
        with self._lock:
            if self._contor > 0:
                self._get_con().commit()
                self._contor     = 0
                self._ultimul_commit = time.time()

    def inchide_conexiune(self):
        self.flush()
        with self._lock:
            if self._con is not None:
                try:
                    self._con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    self._con.execute("PRAGMA journal_mode=DELETE")
                    self._con.close()
                except Exception:
                    pass
                finally:
                    self._con = None
        print(f"[DB-{self.iface_safe}] Conexiune inchisa.")

    def get_pachete_filtrate(self, src_ip=None, dst_ip=None,
                              src_port=None, dst_port=None,
                              protocol=None, tcp_flags=None,
                              min_len=None, max_len=None,
                              ip_exclus=None, limit=500, min_id=None,
                              ts_min=None, ts_max=None):
        cond = []; params = []
        if src_ip   and str(src_ip).strip():
            cond.append("src_ip LIKE ?");    params.append(f"%{src_ip.strip()}%")
        if dst_ip   and str(dst_ip).strip():
            cond.append("dst_ip LIKE ?");    params.append(f"%{dst_ip.strip()}%")
        if src_port and str(src_port).strip():
            cond.append("src_port = ?");     params.append(src_port.strip())
        if dst_port and str(dst_port).strip():
            cond.append("dst_port = ?");     params.append(dst_port.strip())
        if protocol and protocol != "all":
            cond.append("protocol = ?");     params.append(protocol)
        if tcp_flags and tcp_flags != "all":
            cond.append("tcp_flags LIKE ?"); params.append(f"%{tcp_flags}%")
        if min_len is not None:
            cond.append("packet_len >= ?");  params.append(int(min_len))
        if max_len is not None:
            cond.append("packet_len <= ?");  params.append(int(max_len))
        if ts_min is not None:
            cond.append("timestamp >= ?");   params.append(float(ts_min))
        if ts_max is not None:
            cond.append("timestamp <= ?");   params.append(float(ts_max))
        if ip_exclus:
            cond.append("src_ip != ?");      params.append(ip_exclus)
            cond.append("dst_ip != ?");      params.append(ip_exclus)
        if min_id is not None:
            cond.append("id > ?");           params.append(int(min_id))
        where = ("WHERE " + " AND ".join(cond)) if cond else ""
        order = "ORDER BY id ASC" if min_id is not None else "ORDER BY timestamp DESC"
        params.append(limit)
        self.flush()
        with self._lock:
            cur = self._get_con().cursor()
            cur.execute(f"""
                SELECT id,timestamp,src_ip,dst_ip,src_port,dst_port,
                       protocol,packet_len,tcp_flags
                FROM packets {where} {order} LIMIT ?
            """, params)
            rows = [dict(r) for r in cur.fetchall()]
            cur.close()
        return rows

    def get_statistici_ip(self, limit=100, ip_exclus=None):
        filtru_src = "AND src_ip != ?" if ip_exclus else ""
        filtru_dst = "AND dst_ip != ?" if ip_exclus else ""
        params = ([ip_exclus] if ip_exclus else []) + \
                ([ip_exclus] if ip_exclus else []) + \
                [limit]
        self.flush()
        with self._lock:
            cur = self._get_con().cursor()
            cur.execute(f"""
                SELECT ip,
                       SUM(pkt_out) AS pachete_trimise,
                       SUM(pkt_in)  AS pachete_primite,
                       SUM(pkt_out)+SUM(pkt_in) AS pachete_total,
                       ROUND(SUM(bytes_out)/1048576.0,3) AS mb_trimisi,
                       ROUND(SUM(bytes_in) /1048576.0,3) AS mb_primiti,
                       ROUND((SUM(bytes_out)+SUM(bytes_in))*1.0
                             /NULLIF(SUM(pkt_out)+SUM(pkt_in),0),1)
                             AS medie_bytes_pachet
                FROM (
                    SELECT src_ip AS ip, COUNT(*) AS pkt_out, 0 AS pkt_in,
                           SUM(packet_len) AS bytes_out, 0 AS bytes_in
                    FROM packets WHERE src_ip IS NOT NULL {filtru_src} GROUP BY src_ip
                    UNION ALL
                    SELECT dst_ip AS ip, 0 AS pkt_out, COUNT(*) AS pkt_in,
                           0 AS bytes_out, SUM(packet_len) AS bytes_in
                    FROM packets WHERE dst_ip IS NOT NULL {filtru_dst} GROUP BY dst_ip
                )
                GROUP BY ip ORDER BY pachete_total DESC LIMIT ?
            """, params)
            rows = [dict(r) for r in cur.fetchall()]
            cur.close()
        return rows

    def get_ip_uri_unice(self, limit=200, ip_exclus=None):
        self.flush()
        with self._lock:
            cur = self._get_con().cursor()
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

    def get_ip_uri_corespondente(self, ip_gazda, limit=200):
        con = self._get_con()
        cur = con.cursor()
        cur.execute(f"""
            SELECT DISTINCT ip FROM (
                SELECT dst_ip AS ip FROM packets WHERE src_ip = ?
                UNION
                SELECT src_ip AS ip FROM packets WHERE dst_ip = ?
            ) WHERE ip IS NOT NULL AND ip != ?
            LIMIT ?
        """, (ip_gazda, ip_gazda, ip_gazda, limit))
        
        rows = cur.fetchall()
        res = [r[0] if isinstance(r, tuple) else r['ip'] for r in rows]
        cur.close()
        return res

    def get_avg_pachete_per_secunda(self, interval_secunde=60):
        ts_start = time.time() - interval_secunde
        self.flush()
        with self._lock:
            cur = self._get_con().cursor()
            cur.execute(
                "SELECT COUNT(*) AS total FROM packets WHERE timestamp >= ?",
                (ts_start,))
            row = cur.fetchone()
            cur.close()
        if not row or not row["total"]:
            return 0.0
        return round(row["total"] / interval_secunde, 2)

    def get_pachete_per_secunda_per_ip(self, interval_secunde=300,
                                        bucket_secunde=10, ip_exclus=None):
        ts = time.time() - interval_secunde
        ec = "AND src_ip != ?" if ip_exclus else ""
        params_ec = [ip_exclus] if ip_exclus else []
        self.flush()
        with self._lock:
            cur = self._get_con().cursor()
            cur.execute(f"""
                SELECT CAST((timestamp-{ts})/{bucket_secunde} AS INTEGER)
                       *{bucket_secunde}+{ts} AS ts_bucket,
                       src_ip, COUNT(*) AS cnt
                FROM packets
                WHERE timestamp>={ts} AND src_ip IS NOT NULL {ec}
                GROUP BY ts_bucket, src_ip
                ORDER BY ts_bucket, cnt DESC
            """, params_ec)
            rows = [dict(r) for r in cur.fetchall()]
            cur.close()
        return rows

    def get_distributie_protocol_timp(self, interval_secunde=300, bucket_secunde=10):
        ts = time.time() - interval_secunde
        self.flush()
        with self._lock:
            cur = self._get_con().cursor()
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

    def get_sesiuni_anterioare(self) -> list:
        fisiere = []
        for fn in sorted(os.listdir(self.folder_arh), reverse=True):
            if fn.endswith(".db"):
                cale  = os.path.join(self.folder_arh, fn)
                data  = fn.replace(".db", "").replace("_", "-")
                size  = os.path.getsize(cale) // 1024
                fisiere.append({
                    "fisier":  fn,
                    "cale":    cale,
                    "data":    data,
                    "size_kb": size,
                })
        return fisiere