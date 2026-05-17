"""
sudo hping3 --icmp -c 1000 -i u10000 192.168.56.1

sudo hping3 -S -c 500 -i u10000 -p 80 192.168.56.1

sudo nmap -sS 192.168.56.1 -p 1-1000 --min-rate 200
"""
import time, threading
from backup import DestinatiBackup, BackupNoop
from enrichment import EnrichmentService


class DetectorAtac:
    NUME = "Generic"; SEVERITATE = "MEDIE"
    _SUPRESIE_GLOBALA = {}
    _LOCK_SUPRESIE = threading.Lock()

    def __init__(self, db, backup=None, sursa="live", ip_gazda=None, enrichment=None):
        self.db       = db
        self.backup   = backup or BackupNoop()
        self.sursa    = sursa
        self.ip_gazda = ip_gazda   
        self.enrichment = enrichment
        self._reference_time = None
        self._ultimele_alerte = {} 

    def set_reference_time(self, ts):
        self._reference_time = float(ts) if ts is not None else None

    def _now(self):
        return self._reference_time if self._reference_time is not None else time.time()

    def analizeaza(self, fereastra_secunde=60):
        raise NotImplementedError

    def _emite_alerta(self, src_ip=None, dst_ip=None, detalii="",
                      src_port=None, dst_port=None, protocol=None, tip_atac=None):
        src_ip, dst_ip = self._completeaza_ip_uri(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
        )
        tip_emitere = tip_atac or self.NUME
        cheie_alerta = (
            f"{tip_emitere}|{src_ip}|{dst_ip}|{src_port}|{dst_port}|{protocol}"
        )
        timp_curent = self._now()
        cooldown = 180

        with self._LOCK_SUPRESIE:
            ts_flux = self._SUPRESIE_GLOBALA.get(cheie_alerta)
            if ts_flux and (timp_curent - ts_flux) < cooldown:
                return
            self._SUPRESIE_GLOBALA[cheie_alerta] = timp_curent
            self._ultimele_alerte[cheie_alerta] = timp_curent

        context = {}
        if self.enrichment is not None:
            context = self.enrichment.enrich_alert_context(src_ip, dst_ip)
            local_ip = None
            local_port = None
            if self.ip_gazda and src_ip == self.ip_gazda:
                local_ip = src_ip
                local_port = src_port
            elif self.ip_gazda and dst_ip == self.ip_gazda:
                local_ip = dst_ip
                local_port = dst_port
            if local_ip and local_port:
                proc = self.enrichment.resolve_process(local_ip, local_port, protocol)
                if proc:
                    context["local_process"] = proc

        alerta = {"tip_atac": tip_emitere, "severitate": self.SEVERITATE,
                  "src_ip": src_ip, "dst_ip": dst_ip,
                  "detalii": detalii, "timestamp": timp_curent,
                  "context": context}
        self.db.inserare_alerta(
            tip_atac=alerta["tip_atac"], severitate=alerta["severitate"],
            src_ip=alerta["src_ip"], dst_ip=alerta["dst_ip"],
            detalii=alerta["detalii"], sursa=self.sursa,
            context=alerta["context"])
        self.backup.trimite(alerta)
        print(f"[ALERTA] [{self.SEVERITATE}] {tip_emitere} "
              f"| src={src_ip} | {detalii}")

    def _ts(self, f):
        return self._now() - f

    def _excl(self):
        if self.ip_gazda:
            return ("AND src_ip != ? AND dst_ip != ?", [self.ip_gazda, self.ip_gazda],)
        return ("", [])

    def _excl_src(self):
        if self.ip_gazda:
            return "AND src_ip != ?", [self.ip_gazda]
        return "", []

    def _excl_dst(self):
        if self.ip_gazda:
            return "AND dst_ip != ?", [self.ip_gazda]
        return "", []

    def _completeaza_ip_uri(self, src_ip=None, dst_ip=None, src_port=None, dst_port=None, protocol=None):
        if src_ip and dst_ip:
            return src_ip, dst_ip
        try:
            cond = ["timestamp >= ?"]
            params = [self._now() - 180]
            if protocol:
                cond.append("protocol = ?")
                params.append(protocol)
            if src_port and src_port != "-":
                cond.append("src_port = ?")
                params.append(str(src_port))
            if dst_port and dst_port != "-":
                cond.append("dst_port = ?")
                params.append(str(dst_port))
            cur = self.db._get_conexiune().cursor()
            cur.execute(f"""
                SELECT src_ip, dst_ip
                FROM packets
                WHERE {' AND '.join(cond)}
                ORDER BY timestamp DESC
                LIMIT 1
            """, params)
            row = cur.fetchone()
            cur.close()
            if row:
                src_ip = src_ip or row["src_ip"]
                dst_ip = dst_ip or row["dst_ip"]
        except Exception:
            pass
        return src_ip, dst_ip


'''
sudo nmap -sS 192.168.56.1 -p 1-1000 --min-rate 200
sudo nmap -sS 192.168.1.129 -p 1-1000 --min-rate 200
'''
class DetectorPortScan(DetectorAtac):
    NUME = "Port Scan"; SEVERITATE = "RIDICATA"

    def analizeaza(self, fereastra_secunde=60):
        prag = int(self.db.get_config_detector("Port Scan", "prag", 20))
        fw   = int(self.db.get_config_detector("Port Scan", "fereastra", 60))

        excl_sql, excl_p = self._excl_src()
        cur = self.db._get_conexiune().cursor()
        cur.execute(f"""
            SELECT src_ip, dst_ip, COUNT(DISTINCT dst_port) AS p
            FROM packets
            WHERE timestamp >= ?
              AND protocol = 'TCP'
              AND tcp_flags LIKE 'S'
              AND dst_port != '-'
              {excl_sql}
            GROUP BY src_ip, dst_ip
            HAVING p > ?
        """, [self._ts(fw)] + excl_p + [prag])
        for r in cur.fetchall():
            self._emite_alerta(
                src_ip=r["src_ip"],
                dst_ip=r["dst_ip"],
                detalii=f"{r['p']} porturi scanate in {fw}s",
                protocol="TCP")
        cur.close()

'''
# 1000 pachete, cate unul la 10ms — suficient pentru a declansa alerta (prag 100/60s)
sudo hping3 -S -c 500 -i u10000 -p 80 192.168.56.1
u10000 = 10.000 microsecunde = 10ms intre pachete. 1000 pachete in ~10 secunde — declanseaza alerta fara sa blochezi calculatorul.
'''
class DetectorSYNFlood(DetectorAtac):
    NUME = "SYN Flood"; SEVERITATE = "CRITICA"

    def analizeaza(self, fereastra_secunde=10):
        prag_syn_ddos = int(self.db.get_config_detector("DDoS SYN Flood", "prag_syn", 200))
        prag_surse    = int(self.db.get_config_detector("DDoS SYN Flood", "prag_surse", 2))
        fw_ddos       = int(self.db.get_config_detector("DDoS SYN Flood", "fereastra", 60))
        prag_syn_dos  = int(self.db.get_config_detector("DoS SYN Flood", "prag_syn", 300))
        fw_dos        = int(self.db.get_config_detector("DoS SYN Flood", "fereastra", 60))
        fw            = max(fw_ddos, fw_dos)

        excl_sql, excl_p = self._excl_src()
        cur = self.db._get_conexiune().cursor()

        cur.execute(f"""
            SELECT dst_ip, dst_port,
                   COUNT(*) AS s,
                   COUNT(DISTINCT src_ip) AS u,
                   MIN(src_ip) AS src_unica,
                   GROUP_CONCAT(DISTINCT src_ip) AS lista_ip
            FROM packets
            WHERE timestamp >= ?
              AND protocol = 'TCP'
              AND tcp_flags = 'S'
              {excl_sql}
            GROUP BY dst_ip, dst_port
            HAVING s > ?
        """, [self._ts(fw)] + excl_p + [min(prag_syn_ddos, prag_syn_dos)])
        
        rezultate = cur.fetchall()
        for r in rezultate:
            if r["u"] >= prag_surse and r["s"] >= prag_syn_ddos:
                
                ip_list = r["lista_ip"].split(",") if r["lista_ip"] else []
                ip_preview = ", ".join(ip_list[:10])
                if len(ip_list) > 10:
                    ip_preview += f" (+ inca {len(ip_list) - 10} IP-uri)"
                
                detalii = (f"{r['s']} pachete SYN catre portul {r['dst_port']} "
                           f"de la {r['u']} surse in {fw_ddos}s. "
                           f"Surse suspecte: {ip_preview}")

                self._emite_alerta(
                    src_ip="MULTIPLE",
                    dst_ip=r["dst_ip"],
                    detalii=detalii,
                    dst_port=r["dst_port"],
                    protocol="TCP",
                    tip_atac="DDoS SYN Flood")
                    
            elif r["u"] == 1 and r["s"] >= prag_syn_dos:
                self._emite_alerta(
                    src_ip=r["src_unica"],
                    dst_ip=r["dst_ip"],
                    detalii=f"{r['s']} pachete SYN catre portul {r['dst_port']} "
                            f"de la o singura sursa in {fw_dos}s",
                    dst_port=r["dst_port"],
                    protocol="TCP",
                    tip_atac="DoS SYN Flood")
        cur.close()


'''
for i in $(seq 1 20); do sshpass -p "wrong$i" ssh -o StrictHostKeyChecking=no administrator@192.168.56.1 2>/dev/null; done
hydra -l administrator -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.1
'''
class DetectorBruteForce(DetectorAtac):
    NUME = "Brute Force"; SEVERITATE = "RIDICATA"
    PORTURI = {"22": "SSH", "3389": "RDP", "21": "FTP", "23": "Telnet"}

    def analizeaza(self, fereastra_secunde=10):
        prag = int(self.db.get_config_detector("Brute Force", "prag",      10))
        fw   = int(self.db.get_config_detector("Brute Force", "fereastra", 60))

        porturi = list(self.PORTURI.keys())
        ph      = ",".join("?" * len(porturi))

        excl_sql, excl_p = self._excl_src()
        cur = self.db._get_conexiune().cursor()
        cur.execute(f"""
            SELECT src_ip, dst_ip, dst_port, COUNT(*) AS t
            FROM packets
            WHERE timestamp >= ?
              AND protocol = 'TCP'
              AND tcp_flags = 'S'
              AND dst_port IN ({ph})
              {excl_sql}
            GROUP BY src_ip, dst_ip, dst_port
            HAVING t > ?
        """, [self._ts(fw)] + porturi + excl_p + [prag])
        for r in cur.fetchall():
            s = self.PORTURI.get(r["dst_port"], r["dst_port"])
            self._emite_alerta(
                src_ip=r["src_ip"], dst_ip=r["dst_ip"],
                detalii=f"{r['t']} tentative {s} "
                        f"(port {r['dst_port']}) in {fw}s",
                dst_port=r["dst_port"], protocol="TCP")
        cur.close()

'''
for i in $(seq 1 100); do
  dig ANY google.com @8.8.8.8 > /dev/null 2>&1 &
done
wait
'''
class DetectorDNSAmplification(DetectorAtac):
    """Raspunsuri DNS de >prag_ratio mai mari decat cererile -> DDoS reflectat."""
    NUME = "DNS Amplification"; SEVERITATE = "RIDICATA"

    def analizeaza(self, fereastra_secunde=60):
        prag_ratio = float(self.db.get_config_detector(
            "DNS Amplification", "prag_ratio",  5.0))
        prag_volum = int(self.db.get_config_detector(
            "DNS Amplification", "prag_volum",   50))
        fw         = int(self.db.get_config_detector(
            "DNS Amplification", "fereastra",    60))

        excl_sql, excl_p = self._excl_src()
        cur = self.db._get_conexiune().cursor()
        cur.execute(f"""
            SELECT
                AVG(CASE WHEN dst_port = '53' THEN packet_len END) AS mc,
                AVG(CASE WHEN src_port = '53' THEN packet_len END) AS mr,
                COUNT(CASE WHEN src_port = '53' THEN 1 END) AS nr
            FROM packets
            WHERE timestamp >= ?
              AND protocol = 'UDP'
              AND (src_port = '53' OR dst_port = '53')
              {excl_sql}
        """, [self._ts(fw)] + excl_p)
        r = cur.fetchone(); cur.close()
        if not r or not r["mc"] or not r["mr"]:
            return
        ratio = r["mr"] / r["mc"]
        if ratio > prag_ratio and r["nr"] > prag_volum:
            self._emite_alerta(
                detalii=f"Amplificare DNS {ratio:.1f}x "
                        f"({r['nr']} raspunsuri in {fw}s)")

'''
# Script cu intervale regulate de ~5s - std mic = detectat ca beaconing
for i in $(seq 1 30); do
  curl -s --max-time 2 http://192.168.56.1 > /dev/null 2>&1
  ping -c 1 192.168.56.1 > /dev/null 2>&1
  sleep 5
done
'''
class DetectorExfiltrare(DetectorAtac):
    NUME = "Data Exfiltration"; SEVERITATE = "CRITICA"

    _MIN_ESTABILIRE_STD = 24

    def analizeaza(self, fereastra_secunde=60):
        prag_p       = 30       # Minim 30 de pachete
        prag_std     = 0.5      # Permitem o deviatie standard de max 0.5s (ping-ul are ~0.05s)
        prag_b       = 1000     # Minim 1000 bytes in total
        fw           = 120      # Cautam in ultimele 120 de secunde
        prag_med_min = 0.1      # Scazut la 0.1s ca sa nu blocheze ping-ul de 1 secunda

        excl_dst_sql, excl_dst_p = self._excl_dst()
        same_ip_cond = "AND src_ip != dst_ip"

        src_sql, src_p = "", []

        cur = self.db._get_conexiune().cursor()
        cur.execute(f"""
            SELECT src_ip, dst_ip,
                   GROUP_CONCAT(timestamp, ',') AS ts,
                   COUNT(*) AS n,
                   SUM(packet_len) AS b
            FROM packets
            WHERE timestamp >= ?
              {excl_dst_sql}
              {same_ip_cond}
              AND dst_ip NOT LIKE '224.%' 
              AND dst_ip NOT LIKE '239.%'
              AND dst_ip != '255.255.255.255'
              {src_sql}
            GROUP BY src_ip, dst_ip
            HAVING n >= ? AND b >= ?
        """, [self._ts(fw)] + excl_dst_p + src_p + [prag_p, prag_b])

        for r in cur.fetchall():
            tsl = sorted([float(t) for t in r["ts"].split(",")])
            n_iv = len(tsl) - 1
            if n_iv < self._MIN_ESTABILIRE_STD:
                continue
            
            iv  = [tsl[i + 1] - tsl[i] for i in range(n_iv)]
            med = sum(iv) / len(iv)
            std = (sum((x - med) ** 2 for x in iv) / len(iv)) ** 0.5
            
            if med < prag_med_min:
                continue
            
            if std < prag_std:
                self._emite_alerta(
                    src_ip=r["src_ip"],  
                    dst_ip=r["dst_ip"],
                    detalii=f"Beaconing: {r['n']} pachete, "
                            f"{r['b'] // 1024}KB, "
                        f"interval mediu {med:.1f}s (std={std:.2f}s)")
        cur.close()

'''
# 1000 pachete, cate unul la 10ms — suficient pentru a declansa alerta (prag 100/60s)
sudo hping3 --icmp -c 1000 -i u10000 192.168.56.1
'''
class DetectorICMPFlood(DetectorAtac):
    NUME = "ICMP Flood"; SEVERITATE = "MEDIE"

    def analizeaza(self, fereastra_secunde=60):
        prag = int(self.db.get_config_detector("ICMP Flood", "prag",      100))
        fw   = int(self.db.get_config_detector("ICMP Flood", "fereastra",  60))

        excl_sql, excl_p = self._excl_src()
        cur = self.db._get_conexiune().cursor()
        
        cur.execute(f"""
            SELECT src_ip, dst_ip, COUNT(*) AS n
            FROM packets
            WHERE timestamp >= ?
              AND protocol = 'ICMP'
              AND src_port = '8'
              {excl_sql}
            GROUP BY src_ip, dst_ip
            HAVING n > ?
        """, [self._ts(fw)] + excl_p + [prag])

        for r in cur.fetchall():
            self._emite_alerta(
                src_ip=r["src_ip"],
                dst_ip=r["dst_ip"],
                detalii=f"{r['n']} pachete ICMP in {fw}s")
        cur.close()


class DetectorDinamic(DetectorAtac):
    NUME = "Regula Custom"

    def __init__(self, db, backup=None, sursa="live", ip_gazda=None,
                 enrichment=None, reguli_db=None):
        super().__init__(db, backup, sursa, ip_gazda, enrichment)
        self.reguli_db = reguli_db if reguli_db is not None else db

    def analizeaza(self, fereastra_secunde=60):
        for reg in self.reguli_db.get_reguli_active():
            self._aplica_regula(reg)

    def _aplica_regula(self, reg):
        cond = ["timestamp >= ?"]
        p = [self._now() - reg["fereastra_secunde"]]
        if reg.get("protocol") and reg["protocol"] != "all":
            cond.append("protocol = ?"); p.append(reg["protocol"])
        if reg.get("port_destinatie"):
            cond.append("dst_port = ?"); p.append(str(reg["port_destinatie"]))
        if reg.get("tcp_flags_contine"):
            cond.append("tcp_flags LIKE ?")
            p.append(f"%{reg['tcp_flags_contine']}%")
        if self.ip_gazda:
            cond.append("src_ip != ?"); p.append(self.ip_gazda)
            cond.append("dst_ip != ?"); p.append(self.ip_gazda)
        p.append(reg["prag_count"])
        cur = self.db._get_conexiune().cursor()
        cur.execute(f"""
            SELECT src_ip, dst_ip, COUNT(*) AS c
            FROM packets
            WHERE {' AND '.join(cond)}
            GROUP BY src_ip, dst_ip
            HAVING c > ?
        """, p)
        for r in cur.fetchall():
            self.SEVERITATE = reg.get("severitate", "MEDIE")
            self.NUME       = reg.get("nume", "Regula Custom")
            self._emite_alerta(
                src_ip=r["src_ip"], dst_ip=r["dst_ip"],
                detalii=f"Regula '{reg['nume']}': "
                        f"{r['c']} ev. in {reg['fereastra_secunde']}s",
                dst_port=reg.get("port_destinatie"),
                protocol=reg.get("protocol"))
        cur.close()


class ManagerDetectie:
    INTERVAL = 5

    def __init__(self, db, backup=None, sursa="live", ip_gazda=None,
                 enrichment=None, reguli_db=None):
        self.db       = db
        self.backup   = backup or BackupNoop()
        self.sursa    = sursa
        self.ip_gazda = ip_gazda
        self.enrichment = enrichment or EnrichmentService(ip_gazda=ip_gazda)
        self._activ   = False
        self._thread  = None

        args = dict(
            db=db, backup=self.backup, sursa=sursa,
            ip_gazda=ip_gazda, enrichment=self.enrichment
        )
        self.detectoare = [
            DetectorPortScan(**args),
            DetectorSYNFlood(**args),
            DetectorBruteForce(**args),
            DetectorDNSAmplification(**args),
            DetectorExfiltrare(**args),
            DetectorICMPFlood(**args),
            DetectorDinamic(**args, reguli_db=reguli_db or db),
        ]

    def set_reference_time(self, ts):
        for d in self.detectoare:
            if hasattr(d, "set_reference_time"):
                d.set_reference_time(ts)

    def adauga_detector(self, d):
        if self.ip_gazda and not getattr(d, "ip_gazda", None):
            d.ip_gazda = self.ip_gazda
        if getattr(d, "enrichment", None) is None:
            d.enrichment = self.enrichment
        self.detectoare.append(d)

    def ruleaza_o_data(self, reference_time=None):
        if reference_time is not None:
            self.set_reference_time(reference_time)
        print(f"[DETECTIE] Analiza ({len(self.detectoare)} detectori)...")
        for d in self.detectoare:
            try:
                d.analizeaza()
            except Exception as e:
                print(f"[DETECTIE] Eroare {d.__class__.__name__}: {e}")

    def start(self):
        self._activ  = True
        self._thread = threading.Thread(target=self._bucla, daemon=False)
        self._thread.start()
        print(f"[DETECTIE] Pornit (interval {self.INTERVAL}s)")

    def stop(self):
        self._activ = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    def _bucla(self):
        while self._activ:
            self.ruleaza_o_data()
            for _ in range(self.INTERVAL):
                if not self._activ:
                    break
                time.sleep(1)