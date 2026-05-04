"""dashboard_trafic.py - Sectiunea Trafic Live cu filtre avansate."""

from datetime import datetime

import dash
from dash import dcc, html, dash_table, Patch
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate

from dashboard_utils import (
    inp, lbl, card, sectiune_titlu,
    style_header_tabel, style_cell_tabel,
    STYLE_DATA_COND_PROTO, BORDER,
)
from validators import validate_ip, validate_port

_FILTRE = {
    "iface-sel", "f-src-ip", "f-dst-ip", "f-src-port",
    "f-dst-port", "f-min-len", "f-max-len", "f-proto", "f-flags",
}


def _format_pachet(pk: dict) -> dict:
    return {
        "id": pk["id"],
        "time": datetime.fromtimestamp(pk["timestamp"]).strftime("%H:%M:%S"),
        "src_ip": pk["src_ip"] or "-",
        "src_port": pk["src_port"] or "-",
        "dst_ip": pk["dst_ip"] or "-",
        "dst_port": pk["dst_port"] or "-",
        "protocol": pk["protocol"] or "-",
        "packet_len": pk["packet_len"] or 0,
        "tcp_flags": pk["tcp_flags"] or "-",
    }


class SecțiuneTrafic:

    FLAGS_OPTS = [
        {"label": "Toate flagurile", "value": "all"},
        {"label": "SYN (S)",        "value": "S"},
        {"label": "ACK (A)",        "value": "A"},
        {"label": "RST (R)",        "value": "R"},
        {"label": "FIN (F)",        "value": "F"},
        {"label": "PSH (P)",        "value": "P"},
        {"label": "SYN+ACK (SA)",   "value": "SA"},
        {"label": "FIN+ACK (FA)",   "value": "FA"},
    ]
    PROTO_OPTS = [
        {"label": "Toate",         "value": "all"},
        {"label": "TCP",           "value": "TCP"},
        {"label": "UDP",           "value": "UDP"},
        {"label": "ICMP/Altele",   "value": "OTHER"},
    ]
    DD_STYLE = {"backgroundColor": "#1e293b", "color": "#0f172a", "fontSize": "13px"}

    def __init__(self, app_state, ip_gazda: str, prefix: str = "lt"):
        self.state    = app_state
        self.ip_gazda = ip_gazda
        self.P        = prefix

    def layout(self):
        p = self.P
        return html.Div([
            # ── Selector interfata ────────────────────────────────────────────
            html.Div(id=f"{p}-iface-bar",
                     style={"marginBottom": "10px"}),

            # ── Filtre ───────────────────────────────────────────────────────
            card([
                html.Div([
                    html.Div([html.Label("IP Sursa:", style=lbl()),
                              dcc.Input(id=f"{p}-f-src-ip", type="text",
                                        placeholder="ex: 10.0.0.1", debounce=True,
                                        style=inp({"width": "145px"}))]),
                    html.Div([html.Label("IP Destinatie:", style=lbl()),
                              dcc.Input(id=f"{p}-f-dst-ip", type="text",
                                        placeholder="ex: 8.8.8.8", debounce=True,
                                        style=inp({"width": "145px"}))]),
                    html.Div([html.Label("Port Sursa:", style=lbl()),
                              dcc.Input(id=f"{p}-f-src-port", type="text",
                                        placeholder="ex: 443", debounce=True,
                                        style=inp({"width": "85px"}))]),
                    html.Div([html.Label("Port Dest:", style=lbl()),
                              dcc.Input(id=f"{p}-f-dst-port", type="text",
                                        placeholder="ex: 80", debounce=True,
                                        style=inp({"width": "85px"}))]),
                    html.Div([html.Label("Dim. min (B):", style=lbl()),
                              dcc.Input(id=f"{p}-f-min-len", type="number",
                                        placeholder="0", debounce=True,
                                        style=inp({"width": "78px"}))]),
                    html.Div([html.Label("Dim. max (B):", style=lbl()),
                              dcc.Input(id=f"{p}-f-max-len", type="number",
                                        placeholder="∞", debounce=True,
                                        style=inp({"width": "78px"}))]),
                ], style={"display": "flex", "gap": "10px",
                          "flexWrap": "wrap", "marginBottom": "10px"}),
                html.Div([
                    html.Div([html.Label("Protocol:", style=lbl()),
                              dcc.Dropdown(id=f"{p}-f-proto",
                                           options=self.PROTO_OPTS,
                                           value="all", clearable=False,
                                           style={**self.DD_STYLE, "width": "130px"})]),
                    html.Div([html.Label("Flaguri TCP:", style=lbl()),
                              dcc.Dropdown(id=f"{p}-f-flags",
                                           options=self.FLAGS_OPTS,
                                           value="all", clearable=False,
                                           style={**self.DD_STYLE, "width": "160px"})]),
                    html.Span(id=f"{p}-count",
                              style={"alignSelf": "flex-end", "fontSize": "12px",
                                     "color": "#94a3b8", "paddingBottom": "6px"}),
                    html.Span(id=f"{p}-val-msg",
                              style={"alignSelf": "flex-end", "fontSize": "11px",
                                     "color": "#fca5a5", "paddingBottom": "6px"}),
                    html.Button("Cauta", id=f"{p}-search-btn", n_clicks=0,
                                style={"alignSelf": "flex-end",
                                       "background": "#1e40af",
                                       "color": "#93c5fd",
                                       "border": "none", "borderRadius": "6px",
                                       "padding": "6px 12px", "cursor": "pointer"}),
                ], style={"display": "flex", "gap": "10px", "alignItems": "flex-end"}),
                html.Div(
                    "Format: IP ex. 192.168.1.10 | Port 1-65535",
                    style={"fontSize": "11px", "color": "#94a3b8", "marginTop": "8px"},
                ),
            ], {"padding": "14px", "marginBottom": "12px"}),

            # ── Tabel pachete ─────────────────────────────────────────────────
            card([
                sectiune_titlu("Pachete recente"),
                dash_table.DataTable(
                    id=f"{p}-table",
                    columns=[{"name": n, "id": i} for n, i in [
                        ("ID", "id"), ("Ora", "time"), ("IP Sursa", "src_ip"),
                        ("Pt.Src", "src_port"), ("IP Dest", "dst_ip"),
                        ("Pt.Dst", "dst_port"), ("Protocol", "protocol"),
                        ("Bytes", "packet_len"), ("Flags", "tcp_flags")]],
                    data=[], page_size=30, sort_action="native",
                    style_header=style_header_tabel(),
                    style_cell=style_cell_tabel(),
                    style_data_conditional=STYLE_DATA_COND_PROTO,
                    style_table={"overflowX": "auto", "maxHeight": "320px",
                                 "overflowY": "auto"}),
            ], {"marginBottom": "12px"}),

            # ── Tabel statistici IP ───────────────────────────────────────────
            card([
                sectiune_titlu(
                    f"Statistici per IP  (IP gazda exclus: {self.ip_gazda})"),
                dash_table.DataTable(
                    id=f"{p}-stats",
                    columns=[{"name": n, "id": i} for n, i in [
                        ("IP", "ip"),
                        ("Pkt. Trimise", "pachete_trimise"),
                        ("Pkt. Primite", "pachete_primite"),
                        ("Total Pkt.", "pachete_total"),
                        ("MB Trimisi", "mb_trimisi"),
                        ("MB Primiti", "mb_primiti"),
                        ("Medie B/pkt", "medie_bytes_pachet")]],
                    data=[], page_size=20, sort_action="native",
                    style_header=style_header_tabel(),
                    style_cell=style_cell_tabel(),
                    style_table={"overflowX": "auto", "maxHeight": "260px",
                                 "overflowY": "auto"}),
            ]),

            dcc.Interval(id=f"{p}-interval", interval=2000, n_intervals=0),
            dcc.Store(id=f"{p}-iface-sel",
                      data=None),   # numele interfetei selectate
            dcc.Store(id=f"{p}-last-id", data=None),
        ])

    def register_callbacks(self, app):
        p = self.P

        from dashboard_utils import ACCENT, MUTED, CARD, BORDER, TEXT

        @app.callback(
            Output(f"{p}-iface-bar",  "children"),
            Output(f"{p}-iface-sel",  "data"),
            Input(f"{p}-interval",    "n_intervals"),
            Input({"type": f"{p}-iface-btn", "index": dash.ALL}, "n_clicks"),
            prevent_initial_call=False,
        )
        def render_iface_bar(_, clicks):
            import json
            from dash import callback_context
            manageri = self.state.manageri_interfete
            if not manageri:
                return html.Div(), None

            # Determina interfata selectata din click
            selectata = self.state.interfata_selectata
            ctx = callback_context
            if ctx.triggered:
                pid = ctx.triggered[0]["prop_id"]
                if f"{p}-iface-btn" in pid:
                    try:
                        info = json.loads(pid.split(".")[0])
                        selectata = info["index"]
                        self.state.interfata_selectata = selectata
                    except Exception:
                        pass

            butoane = []
            for name in manageri:
                activ = (name == selectata)
                stil  = {
                    "background":   ACCENT if activ else CARD,
                    "color":        "white" if activ else MUTED,
                    "border":       f"1px solid {ACCENT if activ else BORDER}",
                    "borderRadius": "6px",
                    "padding":      "5px 14px",
                    "cursor":       "pointer",
                    "fontSize":     "12px",
                    "fontWeight":   "600",
                    "marginRight":  "6px",
                }
                butoane.append(
                    html.Button(name,
                                id={"type": f"{p}-iface-btn", "index": name},
                                n_clicks=0, style=stil))

            bar = html.Div([
                html.Span("Interfata: ",
                          style={"fontSize": "12px", "color": MUTED,
                                 "marginRight": "8px", "alignSelf": "center"}),
                *butoane,
            ], style={"display": "flex", "alignItems": "center",
                      "padding": "8px 14px",
                      "backgroundColor": CARD,
                      "borderRadius": "8px",
                      "marginBottom": "4px"})
            return bar, selectata

        @app.callback(
            Output(f"{p}-table", "data"),
            Output(f"{p}-count", "children"),
            Output(f"{p}-stats", "data"),
            Output(f"{p}-last-id", "data"),
            Output(f"{p}-val-msg", "children"),
            Input(f"{p}-interval",   "n_intervals"),
            Input(f"{p}-iface-sel",  "data"),
            Input(f"{p}-f-src-ip",   "value"),
            Input(f"{p}-f-dst-ip",   "value"),
            Input(f"{p}-f-src-port", "value"),
            Input(f"{p}-f-dst-port", "value"),
            Input(f"{p}-f-min-len",  "value"),
            Input(f"{p}-f-max-len",  "value"),
            Input(f"{p}-f-proto",    "value"),
            Input(f"{p}-f-flags",    "value"),
            Input(f"{p}-search-btn", "n_clicks"),
            State(f"{p}-last-id", "data"),
        )
        def actualizeaza(_, iface_sel, src_ip, dst_ip, src_port, dst_port,
                         min_len, max_len, proto, flags, _search_clicks, last_id):
            for val in [src_ip, dst_ip]:
                ok, err = validate_ip(val, allow_empty=True)
                if not ok:
                    return [], "0 pachete", [], None, err
            for val in [src_port, dst_port]:
                ok, err = validate_port(val, allow_empty=True)
                if not ok:
                    return [], "0 pachete", [], None, err

            ctx = dash.callback_context
            trig = ctx.triggered[0]["prop_id"] if ctx.triggered else ""
            este_filtru = any(f in trig for f in _FILTRE)
            # Alege sursa de date: per-interfata sau DB principal
            mgr = self.state.get_manager_interfata(iface_sel)

            def _fetch(min_id_val=None):
                kw = dict(
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    protocol=proto, tcp_flags=flags,
                    min_len=min_len, max_len=max_len,
                    limit=500, min_id=min_id_val
                )
                if mgr:
                    return mgr.get_pachete_filtrate(**kw)
                return self.state.db.get_pachete_filtrate(**kw)

            def _stats():
                if mgr:
                    return mgr.get_statistici_ip(limit=100, ip_exclus=self.ip_gazda)
                return self.state.db.get_statistici_ip(limit=100, ip_exclus=self.ip_gazda)

            if este_filtru or last_id is None:
                pachete = _fetch()
                rows = [_format_pachet(pk) for pk in pachete]
                new_id = rows[0]["id"] if rows else None
                return rows, f"{len(rows)} pachete afisate", _stats(), new_id, ""

            pachete_noi = _fetch(min_id_val=last_id)
            stats = _stats()
            if not pachete_noi:
                raise PreventUpdate

            new_rows = [_format_pachet(pk) for pk in pachete_noi]
            new_id = new_rows[0]["id"]
            patched = Patch()
            for row in reversed(new_rows):
                patched.prepend(row)
            return patched, f"+{len(new_rows)} pachete noi", stats, new_id, ""