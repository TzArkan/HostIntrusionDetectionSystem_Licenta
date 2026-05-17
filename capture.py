import time
import socket
import threading
from scapy.all import (
    sniff, IP, TCP, UDP, Ether, conf, IFACES, ICMP,
)
import ipaddress


_VIRTUAL_KEYWORDS = (
    "virtualbox", "vmware", "vmnet", "vbox",
    "hyper-v", "hyper_v", "hyperv",
    "tap", "tun", "loopback", "pseudo",
    "miniport", "wan miniport", "teredo",
    "isatap", "6to4",
    
    "veth", "br-", "docker", "virbr", "lo"
)

_PHYSICAL_KEYWORDS = (
    "wi-fi", "wifi", "wireless", "wlan",
    "ethernet", "eth", "lan", "realtek",
    "intel", "broadcom", "atheros", "qualcomm",
    "gigabit", "network adapter",

    "enp", "wlp", "eno", "ens", "wl"
)


class AnalistPachete:
    def __init__(self, manager_baza_date, interfata=None, interfete_manuale=None, app_state=None):
        self.db                = manager_baza_date
        self.interfata         = interfata
        self.interfete_manuale = interfete_manuale
        self.app_state         = app_state
        self._activ            = threading.Event()
        self._activ.set()
        self._threads          = []
        self._guid_to_name: dict = {}

        self._retele_private = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
        ]

    def _este_privata(self, ip_string):
        try:
            adresa = ipaddress.ip_address(ip_string)
            return any(adresa in net for net in self._retele_private)
        except ValueError:
            return False

    def _este_virtuala(self, name: str) -> bool:
        name_lower = name.lower()
        return any(k in name_lower for k in _VIRTUAL_KEYWORDS)

    def _este_fizica(self, name: str) -> bool:
        name_lower = name.lower()
        return any(k in name_lower for k in _PHYSICAL_KEYWORDS)

    def _gaseste_interfata(self):
        print("[CAPTURE] Interfete disponibile:")
        candidati_fizici  = []
        candidati_altii   = []

        for guid, iface in IFACES.items():
            name = getattr(iface, "name", str(guid))
            ip   = getattr(iface, "ip",   None)
            print(f"  {'[VIRTUAL]' if self._este_virtuala(name) else '[fizica] ':10} " f"{name:50} IP: {ip or '-'}")

            if not ip or not self._este_privata(ip):
                continue
            if ip.startswith("127."):
                continue

            if self._este_virtuala(name):
                continue   

            if self._este_fizica(name):
                candidati_fizici.append((guid, iface, ip, name))
            else:
                candidati_altii.append((guid, iface, ip, name))

        for guid, iface, ip, name in candidati_fizici:
            print(f"[CAPTURE] ✓ Interfata selectata (fizica): {name} ({ip})")
            return guid

        for guid, iface, ip, name in candidati_altii:
            print(f"[CAPTURE] ⚠ Interfata selectata (fallback): {name} ({ip})")
            return guid

        fallback = str(conf.iface)
        print(f"[CAPTURE] ⚠ Folosim interfata implicita Scapy: {fallback}")
        print("[CAPTURE] ATENTIE: Verifica manual daca e interfata corecta!")
        return fallback

    def _gestioneaza_pachet(self, pachet, interfata_manager=None):
        if IP not in pachet:
            return

        src_ip    = pachet[IP].src
        dst_ip    = pachet[IP].dst
        protocol  = "OTHER"
        src_port  = "-"
        dst_port  = "-"
        tcp_flags = None

        if TCP in pachet:
            protocol  = "TCP"
            src_port  = str(pachet[TCP].sport)
            dst_port  = str(pachet[TCP].dport)
            flag_map  = {
                0x01: "F", 0x02: "S", 0x04: "R",
                0x08: "P", 0x10: "A", 0x20: "U",
            }
            flags_int = int(pachet[TCP].flags)
            tcp_flags = "".join(v for k, v in flag_map.items() if flags_int & k) or "0"

        elif UDP in pachet:
            protocol = "UDP"
            src_port = str(pachet[UDP].sport)
            dst_port = str(pachet[UDP].dport)

        elif ICMP in pachet:
            protocol = "ICMP"      
            src_port = str(pachet[ICMP].type)  
            dst_port = str(pachet[ICMP].code)  

        params = dict(
            timestamp  = time.time(),
            src_ip     = src_ip,
            dst_ip     = dst_ip,
            src_port   = src_port,
            dst_port   = dst_port,
            protocol   = protocol,
            packet_len = len(pachet),
            tcp_flags  = tcp_flags,
        )
        try:
            self.db.inserare_pachet(**params)

            if interfata_manager is not None:
                interfata_manager.inserare_pachet(**params)
            elif self.app_state and self.app_state.manageri_interfete:
                iface_raw  = getattr(pachet, "sniffed_on", None)
                iface_name = self._guid_to_name.get(str(iface_raw), str(iface_raw) if iface_raw else None)
                if iface_name and iface_name in self.app_state.manageri_interfete:
                    self.app_state.manageri_interfete[iface_name].inserare_pachet(
                        **params)
        except Exception as e:
            print(f"[CAPTURE] Eroare la inserare in DB: {e}")

    @staticmethod
    def _get_ip_gazda() -> str | None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return None

    def _gaseste_toate_interfetele(self) -> list:
        fizice   = []
        virtuale = []

        for guid, iface in IFACES.items():
            name = getattr(iface, "name", str(guid))
            ip   = getattr(iface, "ip",   None)

            if not ip or ip.startswith("127."):
                continue
            try:
                if ipaddress.ip_address(ip).is_loopback:
                    continue
            except ValueError:
                continue

            skip_keywords = ("hyper-v", "hyperv", "wan miniport","teredo", "isatap", "6to4", "pseudo",)
            name_lower = name.lower()
            if any(k in name_lower for k in skip_keywords):
                continue

            if self._este_fizica(name):
                fizice.append((guid, name, ip, "fizica"))
            elif any(k in name_lower for k in ("virtualbox", "vmware","vmnet", "vbox", "tap", "host-only")):
                virtuale.append((guid, name, ip, "virtuala"))

        guids    = []
        detalii  = []

        for guid, name, ip, tip in fizice:
            guids.append(guid)
            detalii.append({"name": name, "ip": ip, "tip": tip})
            self._guid_to_name[str(guid)] = name
            self._guid_to_name[name]      = name   
            print(f"[CAPTURE] ✓ {tip:8} {name} ({ip})")

        for guid, name, ip, tip in virtuale:
            guids.append(guid)
            detalii.append({"name": name, "ip": ip, "tip": tip})
            self._guid_to_name[str(guid)] = name
            self._guid_to_name[name]      = name
            print(f"[CAPTURE] ✓ {tip:8} {name} ({ip})")

        if self.app_state is not None:
            self.app_state.interfete_active = detalii

        return guids

    def _rezolva_guid(self, name: str):
        name_lower = name.lower().strip()
        for guid, iface in IFACES.items():
            iface_name = getattr(iface, "name", "").lower().strip()
            if name_lower in iface_name or iface_name in name_lower:
                return guid
        return name

    def _listeaza_toate(self):
        print("[CAPTURE] Toate interfetele disponibile: ")
        for guid, iface in IFACES.items():
            name = getattr(iface, "name", str(guid))
            ip   = getattr(iface, "ip",   "-")
            print(f"[CAPTURE]   {name:50} IP: {ip}")
        print("[CAPTURE] Am terminat de afisat interfetele")

    def start_captura_pachete(self):
        if self.interfete_manuale:
            ifaces  = [self._rezolva_guid(n) for n in self.interfete_manuale]
            detalii = [{"name": n, "ip": "—", "tip": "manuala"}
                       for n in self.interfete_manuale]
            for n in self.interfete_manuale:
                print(f"[CAPTURE] ✓ manuala  {n}")
            if self.app_state is not None:
                self.app_state.interfete_active = detalii
        elif self.interfata:
            ifaces = [self._rezolva_guid(self.interfata)]
            if self.app_state is not None:
                self.app_state.interfete_active = [
                    {"name": str(self.interfata), "ip": "—", "tip": "manuala"}
                ]
        else:
            ifaces = self._gaseste_toate_interfetele()

        if not ifaces:
            print("[CAPTURE] ⚠ Nicio interfata detectata automat!")
            self._listeaza_toate()
            ifaces = [str(conf.iface)]
            print(f"[CAPTURE] ⚠ Fallback: {ifaces[0]}")

        bpf_filter = "ip"
        print(f"[CAPTURE] Filtru BPF: {bpf_filter}")

        managers = {}
        if self.app_state:
            managers = self.app_state.manageri_interfete

        active = self.app_state.interfete_active if self.app_state else []

        def _face_callback(mgr):
            def cb(pkt):
                self._gestioneaza_pachet(pkt, interfata_manager=mgr)
            return cb

        threads = []

        for i, guid in enumerate(ifaces):
            mgr = None
            if i < len(active):
                iface_name = active[i].get("name", "")
                mgr = managers.get(iface_name)

            callback = _face_callback(mgr)
            def _sniff_loop(g=guid, cb=callback):
                while self._activ.is_set():
                    sniff(
                        iface=g,
                        prn=cb,
                        store=False,
                        filter=bpf_filter,
                        timeout=1,
                        promisc=False,
                    )

            t = threading.Thread(
                target=_sniff_loop,
                daemon=False,
                name=f"capture-{guid}")
            t.start()
            threads.append(t)
            print(f"[CAPTURE] Thread pornit: {guid}"
                  + (f" -> {mgr.interfata}" if mgr else " (fara manager interfata)"))
                  
            time.sleep(0.5)

        self._threads = threads
        for t in threads:
            t.join()

    def stop(self):
        self._activ.clear()
        for t in self._threads:
            if t.is_alive():
                t.join(timeout=2)