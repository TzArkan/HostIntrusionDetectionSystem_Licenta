"""
dashboard_comunicatii.py - Sectiunea Comunicatii.
IP gazda selectabil dintre interfetele active (din app_state.interfete_active).
Dropdown IP corespondent, filtre port, interval timp.
"""
import time
from datetime import datetime

from dash import dcc, html, dash_table
from dash.dependencies import Input, Output, State

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
                # ── IP-uri + interval ─────────────────────────────────────────
                html.Div([
                    # IP Gazda — dropdown selectabil
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

                    # IP corespondent
                    html.Div([
                        html.Label("Comunica cu:", style=lbl()),
                        dcc.Dropdown(id=f"{p}-ip2", options=[], value=None,
                                     style={**self.DD_STYLE, "width": "220px"}),
                    ]),

                    html.Div([
                        html.Label("Interval:", style=lbl()),
                        dcc.Dropdown(id=f"{p}-interval",
                                     options=self.INTERVAL_OPTS,
                                     value="3600", clearable=False,
                                     style={**self.DD_STYLE, "width": "200px"}),
                    ]),
                ], style={"display": "flex", "gap": "16px",
                          "alignItems": "flex-end",
                          "marginBottom": "12px", "flexWrap": "wrap"}),

                # ── Filtre porturi + buton ────────────────────────────────────
                html.Div([
                    html.Div([html.Label("Port Sursa:", style=lbl()),
                              dcc.Input(id=f"{p}-src-port", type="text",
                                        placeholder="ex: 443", debounce=True,
                                        style=inp({"width": "90px"}))]),
                    html.Div([html.Label("Port Destinatie:", style=lbl()),
                              dcc.Input(id=f"{p}-dst-port", type="text",
                                        placeholder="ex: 80", debounce=True,
                                        style=inp({"width": "90px"}))]),
                    html.Button("Cauta", id=f"{p}-btn",
                                style={**btn(), "alignSelf": "flex-end"}),
                    html.Span(id=f"{p}-info",
                              style={"alignSelf": "flex-end", "color": MUTED,
                                     "fontSize": "12px",
                                     "paddingBottom": "7px"}),
                ], style={"display": "flex", "gap": "10px",
                          "alignItems": "flex-end"}),
                html.Div("Format port: 1-65535",
                         style={"fontSize": "11px", "color": MUTED,
                                "marginTop": "8px"}),
            ], {"padding": "14px", "marginBottom": "12px"}),

            # ── Rezultate ─────────────────────────────────────────────────────
            html.Div(id=f"{p}-result",
                     style={"backgroundColor": CARD, "borderRadius": "10px",
                            "padding": "16px"}),

            dcc.Interval(id=f"{p}-ip-refresh", interval=10000, n_intervals=0),
        ])

    def register_callbacks(self, app):
        p = self.P

        # Refresh optiuni IP Gazda (interfete active) + lista IP corespondent
        @app.callback(
            Output(f"{p}-ip1", "options"),
            Output(f"{p}-ip2", "options"),
            Input(f"{p}-ip-refresh", "n_intervals"),
            State(f"{p}-ip1", "value"),
        )
        def refresh_ip(_, ip1_curent):
            # Optiuni IP gazda din interfetele active
            opts_ip1 = self._ip_uri_gazda()

            # IP-ul gazda selectat curent (sau primul disponibil)
            ip_exclus = ip1_curent or (
                opts_ip1[0]["value"] if opts_ip1 else self.ip_gazda)

            # Toate IP-urile din DB, exclus IP-ul gazda selectat
            ip_uri = self.state.db.get_ip_uri_unice(
                limit=200, ip_exclus=ip_exclus)
            opts_ip2 = [{"label": ip, "value": ip} for ip in ip_uri]

            return opts_ip1, opts_ip2

        # Cautare comunicatii
        @app.callback(
            Output(f"{p}-result", "children"),
            Output(f"{p}-info",   "children"),
            Input(f"{p}-btn",  "n_clicks"),
            State(f"{p}-ip1",      "value"),
            State(f"{p}-ip2",      "value"),
            State(f"{p}-interval", "value"),
            State(f"{p}-src-port", "value"),
            State(f"{p}-dst-port", "value"),
            prevent_initial_call=True,
        )
        def cauta(_, ip1, ip2, interval_val, src_port, dst_port):
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

            interval_sec = None if interval_val == "all" else int(interval_val)
            pachete = self.state.db.get_pachete_intre_ip(
                ip1, ip2,
                interval_secunde=interval_sec,
                src_port=src_port,
                dst_port=dst_port,
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

            return tabel, f"{len(pachete)} pachete intre {ip1} si {ip2}"