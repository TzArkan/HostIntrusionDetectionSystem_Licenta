from __future__ import annotations

import ipaddress
import socket
import threading
import time
import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from typing import Any

try:
    import psutil
except Exception: 
    psutil = None

try:
    import geoip2.database
except Exception: 
    geoip2 = None
else:
    geoip2 = geoip2


class TTLCache:

    def __init__(self):
        self._data: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            expires_at, value = item
            if expires_at < time.time():
                self._data.pop(key, None)
                return None
            return value

    def set(self, key: str, value: Any, ttl_sec: float):
        with self._lock:
            self._data[key] = (time.time() + ttl_sec, value)


class EnrichmentService:

    def __init__(self, ip_gazda: str | None = None, geoip_dir: str | None = None):
        self.ip_gazda = ip_gazda
        self.geoip_dir = geoip_dir
        self.cache = TTLCache()
        self.metrics = {
            "dns_total": 0,
            "dns_cache_hit": 0,
            "dns_timeout": 0,
            "process_total": 0,
            "process_cache_hit": 0,
            "geo_total": 0,
            "geo_cache_hit": 0,
            "errors": 0,
        }
        self._metrics_lock = threading.Lock()
        self._geo_city_reader = None
        self._geo_asn_reader = None
        self._geo_lock = threading.Lock()

    def _inc(self, key: str):
        with self._metrics_lock:
            self.metrics[key] = self.metrics.get(key, 0) + 1

    @staticmethod
    def _is_public_ip(ip: str | None) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
            return not (
                addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast
            )
        except ValueError:
            return False

    @staticmethod
    def _with_timeout(fn, timeout_sec: float):
        with ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(fn)
            return fut.result(timeout=timeout_sec)

    def resolve_domain(self, ip: str | None, timeout_sec: float = 0.25) -> str | None:
        self._inc("dns_total")
        if not self._is_public_ip(ip):
            return None

        key = f"dns:{ip}"
        cached = self.cache.get(key)
        if cached is not None:
            self._inc("dns_cache_hit")
            return cached or None

        try:
            domain = self._with_timeout(lambda: socket.gethostbyaddr(ip)[0], timeout_sec)
            self.cache.set(key, domain, ttl_sec=3600)
            return domain
        except TimeoutError:
            self._inc("dns_timeout")
            self.cache.set(key, "", ttl_sec=120)
            return None
        except Exception:
            self._inc("errors")
            self.cache.set(key, "", ttl_sec=300)
            return None

    def resolve_process(
        self,
        local_ip: str | None,
        local_port: str | int | None,
        protocol: str | None,
    ) -> dict | None:
        self._inc("process_total")
        if psutil is None:
            return None
        if not local_ip or str(local_port) in ("", "-", "None", "none", "null"):
            return None
        if self.ip_gazda and local_ip != self.ip_gazda:
            return None
        try:
            port = int(local_port)
        except Exception:
            return None

        proto = (protocol or "").upper()
        key = f"proc:{local_ip}:{port}:{proto}"
        cached = self.cache.get(key)
        if cached is not None:
            self._inc("process_cache_hit")
            return cached or None

        kind = "tcp" if proto == "TCP" else "udp" if proto == "UDP" else "inet"
        try:
            for conn in psutil.net_connections(kind=kind):
                if not conn.laddr:
                    continue
                lip, lport = conn.laddr[0], conn.laddr[1]
                if lip == local_ip and lport == port:
                    pid = conn.pid
                    if not pid:
                        continue
                    name = None
                    exe = None
                    try:
                        proc = psutil.Process(pid)
                        name = proc.name()
                        exe = proc.exe()
                    except Exception:
                        pass
                    result = {"pid": pid, "name": name, "exe": exe}
                    self.cache.set(key, result, ttl_sec=5)
                    return result
        except Exception:
            self._inc("errors")
            return None

        self.cache.set(key, {}, ttl_sec=2)
        return None

    def _ensure_geo_readers(self):
        if geoip2 is None or not self.geoip_dir:
            return
        with self._geo_lock:
            if self._geo_city_reader is None:
                city_path = os.path.join(self.geoip_dir, "GeoLite2-City.mmdb")
                try:
                    self._geo_city_reader = geoip2.database.Reader(city_path)
                except Exception:
                    self._geo_city_reader = False
            if self._geo_asn_reader is None:
                asn_path = os.path.join(self.geoip_dir, "GeoLite2-ASN.mmdb")
                try:
                    self._geo_asn_reader = geoip2.database.Reader(asn_path)
                except Exception:
                    self._geo_asn_reader = False

    def resolve_geo_asn(self, ip: str | None) -> dict | None:
        self._inc("geo_total")
        if not self._is_public_ip(ip):
            return None
        key = f"geo:{ip}"
        cached = self.cache.get(key)
        if cached is not None:
            self._inc("geo_cache_hit")
            return cached or None

        self._ensure_geo_readers()
        city = None
        country = None
        asn = None
        org = None
        try:
            if self._geo_city_reader and self._geo_city_reader is not False:
                rec = self._geo_city_reader.city(ip)
                city = rec.city.name
                country = rec.country.iso_code or rec.country.name
            if self._geo_asn_reader and self._geo_asn_reader is not False:
                rec = self._geo_asn_reader.asn(ip)
                asn = rec.autonomous_system_number
                org = rec.autonomous_system_organization
        except Exception:
            self._inc("errors")

        if not any([city, country, asn, org]):
            self.cache.set(key, {}, ttl_sec=1800)
            return None
        result = {"city": city, "country": country, "asn": asn, "org": org}
        self.cache.set(key, result, ttl_sec=3600)
        return result

    def enrich_alert_context(self, src_ip: str | None, dst_ip: str | None) -> dict:
        context = {
            "src_domain": self.resolve_domain(src_ip),
            "dst_domain": self.resolve_domain(dst_ip),
            "src_geo": self.resolve_geo_asn(src_ip),
            "dst_geo": self.resolve_geo_asn(dst_ip),
        }
        return context

