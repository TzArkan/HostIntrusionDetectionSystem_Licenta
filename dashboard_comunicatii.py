"""
dashboard_comunicatii.py - Sectiunea Comunicatii.
IP gazda selectabil dintre interfetele active (din app_state.interfete_active).
Dropdown IP corespondent, filtre port, protocol, flags, interval relativ sau absolut.
"""
import time
from datetime import datetime

from dash import dcc, html, dash_table
from dash.dependencies import Input, Output, State

from dashboard_trafic import _parse_ts_input
from dashboard_utils import (
    inp, lbl, btn, card,
    style_header_tabel, style_cell_tabel,
    STYLE_DATA_COND_PROTO, ACCENT, MUTED, BORDER, CARD, DARK,
)
from validators import validate_port


class SecțiuneComunicatii:

    INTERVAL_OPTS = [
        {"label": "Ultimele 30 minute", "value": "1800"},
        {"label": "Ultima ora",          "value": "3600"},
        {"label": "Ultimele 5 ore",      "value": "18000"},
        {"label": "Toate",               "value": "all"},
    ]
    FLAGS_OPTS = [
        {"label": "Toate flagurile", "value": "all"},
        {"label": "SYN (S)",        "value": "S"},
        {"label": "ACK (A)",        "value": "A"},
        {"label": "RST (R)",        "value": "R"},
        {"label": "FIN (F)",        "value": "F"},
        {"label": "PSH (P)",        "value": "P"},
        {"label": "SYN+ACK (SA)",   "value": "SA"},
    ]
    PROTO_OPTS = [
        {"label": "Toate",       "value": "all"},
        {"label": "TCP",         "value": "TCP"},
        {"label": "UDP",         "value": "UDP"},
        {"label": "ICMP/Altele", "value": "OTHER"},
    ]
    DD_STYLE = {"backgroundColor": CARD, "color": DARK, "fontSize": "13px"}

    def __init__(self, app_state, ip_gazda: str, prefix: str = "lc"):
        self.state    = app_state
        self.ip_gazda = ip_gazda   # IP implicit (fallback)
        self.P        = prefix

    def _ip_uri_gazda(self) -> list[dict]:
        """
        Returneaza optiunile pentru dropdown-ul IP gazda:
        - toate IP-urile interfetelor active detectate de Scapy
        - fallback: ip_gazda din constructor
        """
        interfete = self.state.interfete_active
        if interfete:
            vazute = set()
            opts   = []
            for iface in interfete:
                ip = iface.get("ip", "")
                if ip and ip != "—" and ip not in vazute:
                    vazute.add(ip)
                    tip   = iface.get("tip", "")
                    name  = iface.get("name", "")
                    label = f"{ip}  ({name})"
                    opts.append({"label": label, "value": ip})
            if opts:
                return opts
        return [{"label": self.ip_gazda, "value": self.ip_gazda}]

    def layout(self):
        p    = self.P
        opts = self._ip_uri_gazda()
        val_implicit = opts[0]["value"] if opts else self.ip_gazda

        return html.Div([
            card([
                # ── IP-uri + interval relativ ─────────────────────────────────
                html.Div([
                    html.Div([
                        html.Label("IP Gazda:", style=lbl()),
                        dcc.Dropdown(
                            id=f"{p}-ip1",
                            options=opts,
                            value=val_implicit,
                            clearable=False,
                            style={**self.DD_STYLE, "width": "260px"}),
                    ]),
                    html.Span("↔",
                              style={"fontSize": "20px", "color": MUTED,
                                     "alignSelf": "flex-end",
                                     "paddingBottom": "8px"}),
                    html.Div([
                        html.Label("Comunica cu:", style=lbl()),
                        dcc.Dropdown(id=f"{p}-ip2", options=[], value=None,
                                     style={**self.DD_STYLE, "width": "220px"}),
                    ]),
                    html.Div([
                        html.Label("Interval relativ:", style=lbl()),
                        dcc.Dropdown(id=f"{p}-interval",
                                     options=self.INTERVAL_OPTS,
                                     value="3600", clearable=False,
                                     style={**self.DD_STYLE, "width": "200px"}),
                    ]),
                ], style={"display": "flex", "gap": "16px",
                          "alignItems": "flex-end",
                          "marginBottom": "12px", "flexWrap": "wrap"}),

                # ── Filtre porturi, protocol, flags, interval absolut ───────
                html.Div([
                    html.Div([html.Label("Port Sursa:", style=lbl()),
                              dcc.Input(id=f"{p}-src-port", type="text",
                                        placeholder="ex: 443", debounce=True,
                                        style=inp({"width": "90px"}))]),
                    html.Div([html.Label("Port Destinatie:", style=lbl()),
                              dcc.Input(id=f"{p}-dst-port", type="text",
                                        placeholder="ex: 80", debounce=True,
                                        style=inp({"width": "90px"}))]),
                    html.Div([html.Label("Protocol:", style=lbl()),
                              dcc.Dropdown(id=f"{p}-proto",
                                           options=self.PROTO_OPTS,
                                           value="all", clearable=False,
                                           style={**self.DD_STYLE, "width": "125px"})]),
                    html.Div([html.Label("Flaguri TCP:", style=lbl()),
                              dcc.Dropdown(id=f"{p}-flags",
                                           options=self.FLAGS_OPTS,
                                           value="all", clearable=False,
                                           style={**self.DD_STYLE, "width": "150px"})]),
                ], style={"display": "flex", "gap": "10px",
                          "alignItems": "flex-end", "flexWrap": "wrap",
                          "marginBottom": "10px"}),

                html.Div([
                    html.Div([html.Label("Start interval (absolut):", style=lbl()),
                              dcc.Input(id=f"{p}-ts-start", type="text",
                                        placeholder="YYYY-MM-DD HH:MM:SS",
                                        debounce=True,
                                        style=inp({"width": "175px"}))]),
                    html.Div([html.Label("End interval (absolut):", style=lbl()),
                              dcc.Input(id=f"{p}-ts-end", type="text",
                                        placeholder="YYYY-MM-DD HH:MM:SS",
                                        debounce=True,
                                        style=inp({"width": "175px"}))]),
                    html.Button("Cauta", id=f"{p}-btn",
                                style={**btn(), "alignSelf": "flex-end"}),
                    html.Span(id=f"{p}-info",
                              style={"alignSelf": "flex-end", "color": MUTED,
                                     "fontSize": "12px",
                                     "paddingBottom": "7px"}),
                ], style={"display": "flex", "gap": "10px",
                          "alignItems": "flex-end", "flexWrap": "wrap"}),

                html.Div(
                    "Dacă completezi Start și End, filtrul relativ de mai sus "
                    "este ignorat pentru căutare. Lista „Comunică cu” se "
                    "reîmprospătează la fiecare ciclu și se resetează selecția.",
                    style={"fontSize": "11px", "color": MUTED,
                           "marginTop": "8px", "lineHeight": "1.4"},
                ),
                html.Div("Format port: 1-65535",
                         style={"fontSize": "11px", "color": MUTED,
                                "marginTop": "4px"}),
            ], {"padding": "14px", "marginBottom": "12px"}),

            html.Div(id=f"{p}-result",
                     style={"backgroundColor": CARD, "borderRadius": "10px",
                            "padding": "16px"}),

            dcc.Interval(id=f"{p}-ip-refresh", interval=10000, n_intervals=0),
        ])

    def register_callbacks(self, app):
        p = self.P

        @app.callback(
            Output(f"{p}-ip1", "options"),
            Output(f"{p}-ip2", "options"),
            Input(f"{p}-ip-refresh", "n_intervals"),
            Input(f"{p}-ip1", "value"), # Input declanșează actualizarea imediat la click
        )
        def refresh_ip(_, ip1_sel):
            # 1. Obținem interfețele active pentru primul dropdown
            opts_ip1 = self._ip_uri_gazda()
            
            # 2. Determinăm IP-ul pentru care căutăm corespondenți
            # Dacă ip1_sel e None, folosim primul IP disponibil din interfețe sau IP-ul gazdă global
            target_ip = ip1_sel or (opts_ip1[0]["value"] if opts_ip1 else self.ip_gazda)
            
            # 3. Preluăm IP-urile corespondente
            if target_ip:
                ip_uri = self.state.db.get_ip_uri_corespondente(target_ip, limit=200)
            else:
                ip_uri = []
                
            opts_ip2 = [{"label": ip, "value": ip} for ip in ip_uri]
            
            # Returnăm opțiunile pentru ambele dropdown-uri
            return opts_ip1, opts_ip2

        @app.callback(
            Output(f"{p}-result", "children"),
            Output(f"{p}-info",   "children"),
            Input(f"{p}-btn",  "n_clicks"),
            State(f"{p}-ip1",      "value"),
            State(f"{p}-ip2",      "value"),
            State(f"{p}-interval", "value"),
            State(f"{p}-src-port", "value"),
            State(f"{p}-dst-port", "value"),
            State(f"{p}-proto",    "value"),
            State(f"{p}-flags",    "value"),
            State(f"{p}-ts-start", "value"),
            State(f"{p}-ts-end",   "value"),
            prevent_initial_call=True,
        )
        def cauta(_, ip1, ip2, interval_val, src_port, dst_port,
                  proto, flags, ts_start, ts_end):
            ok_sp, err_sp = validate_port(src_port, allow_empty=True)
            ok_dp, err_dp = validate_port(dst_port, allow_empty=True)
            if not ok_sp:
                return html.P(err_sp, style={"color": "#fca5a5"}), ""
            if not ok_dp:
                return html.P(err_dp, style={"color": "#fca5a5"}), ""
            if not ip2:
                return html.P("Selecteaza un IP corespondent.",
                              style={"color": MUTED}), ""
            if not ip1:
                ip1 = self.ip_gazda

            ts_min = _parse_ts_input(ts_start)
            ts_max = _parse_ts_input(ts_end)
            has_any = bool((ts_start and str(ts_start).strip()) or (
                ts_end and str(ts_end).strip()))
            if has_any and (ts_min is None or ts_max is None):
                return html.P(
                    "Interval absolut invalid sau incomplet (completează "
                    "Start și End sau lasă ambele goale).",
                    style={"color": "#fca5a5"}), ""
            if ts_min is not None and ts_max is not None and ts_min > ts_max:
                return html.P("Start trebuie ≤ End.",
                              style={"color": "#fca5a5"}), ""

            use_abs = ts_min is not None and ts_max is not None
            if use_abs:
                interval_sec = None
            else:
                interval_sec = (None if interval_val == "all"
                                else int(interval_val))

            pachete = self.state.db.get_pachete_intre_ip(
                ip1, ip2,
                interval_secunde=interval_sec,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                tcp_flags=flags,
                ts_min=ts_min if use_abs else None,
                ts_max=ts_max if use_abs else None,
                limit=500)

            if not pachete:
                return html.P("Nicio comunicare gasita.",
                              style={"color": MUTED}), ""

            rows = [{
                "time":     datetime.fromtimestamp(
                            pk["timestamp"]).strftime("%H:%M:%S"),
                "directie": f"{pk['src_ip']} → {pk['dst_ip']}",
                "src_port": pk["src_port"],
                "dst_port": pk["dst_port"],
                "protocol": pk["protocol"],
                "len":      pk["packet_len"],
                "flags":    pk["tcp_flags"] or "-",
            } for pk in pachete]

            tabel = dash_table.DataTable(
                columns=[{"name": n, "id": i} for n, i in [
                    ("Ora", "time"), ("Directie", "directie"),
                    ("Pt.Src", "src_port"), ("Pt.Dst", "dst_port"),
                    ("Protocol", "protocol"), ("Bytes", "len"),
                    ("Flags", "flags")]],
                data=rows, page_size=40, sort_action="native",
                style_header=style_header_tabel(),
                style_cell=style_cell_tabel(),
                style_data_conditional=STYLE_DATA_COND_PROTO,
                style_table={"overflowX": "auto",
                             "maxHeight": "550px", "overflowY": "auto"})

            filtru_t = "interval absolut" if use_abs else "interval relativ"
            return tabel, f"{len(pachete)} pachete ({filtru_t}) intre {ip1} si {ip2}"
