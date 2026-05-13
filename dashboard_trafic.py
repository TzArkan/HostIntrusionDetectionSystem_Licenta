"""dashboard_trafic.py - Sectiunea Trafic Live cu filtre avansate."""

from datetime import datetime, date

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
    "f-ts-start", "f-ts-end",
}


def _parse_ts_input(val) -> float | None:
    """Parseaza timp pentru filtru istoric; suporta data completa sau doar ora (azi)."""
    if val is None or not str(val).strip():
        return None
    s = str(val).strip()
    fmts = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%d.%m.%Y %H:%M:%S",
        "%d.%m.%Y %H:%M",
    )
    for fmt in fmts:
        try:
            return datetime.strptime(s, fmt).timestamp()
        except ValueError:
            pass
    try:
        tt = datetime.strptime(s, "%H:%M:%S").time()
        return datetime.combine(date.today(), tt).timestamp()
    except ValueError:
        pass
    try:
        tt = datetime.strptime(s, "%H:%M").time()
        return datetime.combine(date.today(), tt).timestamp()
    except ValueError:
        pass
    return None


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
                    html.Div([html.Label("Start timp:", style=lbl()),
                              dcc.Input(id=f"{p}-f-ts-start", type="text",
                                        placeholder="2026-05-12 14:00:00",
                                        debounce=True,
                                        style=inp({"width": "168px"}))]),
                    html.Div([html.Label("End timp:", style=lbl()),
                              dcc.Input(id=f"{p}-f-ts-end", type="text",
                                        placeholder="2026-05-12 14:05:00",
                                        debounce=True,
                                        style=inp({"width": "168px"}))]),
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
                ], style={"display": "flex", "gap": "10px", "alignItems": "flex-end",
                          "flexWrap": "wrap"}),
                html.Div(
                    "Format timp: YYYY-MM-DD HH:MM:SS sau HH:MM:SS (azi). "
                    "Cu Start+End valid, traficul live se ingheata pe acel interval.",
                    style={"fontSize": "11px", "color": "#94a3b8", "marginTop": "8px"},
                ),
                html.Div(
                    "Format: IP ex. 192.168.1.10 | Port 1-65535",
                    style={"fontSize": "11px", "color": "#94a3b8", "marginTop": "4px"},
                ),
            ], {"padding": "14px", "marginBottom": "12px"}),

            # ── Tabel pachete ─────────────────────────────────────────────────
            card([
                sectiune_titlu("Pachete recente"),
                html.Div([
                    html.Button(
                        "⏸ Pauză live",
                        id=f"{p}-pause-btn",
                        n_clicks=0,
                        style={
                            "background": "#334155",
                            "color": "#e2e8f0",
                            "border": f"1px solid {BORDER}",
                            "borderRadius": "6px",
                            "padding": "6px 14px",
                            "cursor": "pointer",
                            "fontSize": "12px",
                            "fontWeight": "600",
                        },
                    ),
                    html.Span(
                        id=f"{p}-freeze-hint",
                        style={
                            "fontSize": "11px",
                            "color": "#94a3b8",
                            "marginLeft": "12px",
                        },
                    ),
                ], style={
                    "display": "flex",
                    "alignItems": "center",
                    "marginBottom": "10px",
                    "flexWrap": "wrap",
                }),
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

            dcc.Interval(id=f"{p}-interval", interval=2000, n_intervals=0),
            dcc.Store(id=f"{p}-iface-sel",
                      data=None),   # numele interfetei selectate
            dcc.Store(id=f"{p}-last-id", data=None),
            dcc.Store(id=f"{p}-manual-pause", data=False),
            dcc.Store(id=f"{p}-applied-filters", data={}),
        ])

    def register_callbacks(self, app):
        p = self.P

        from dashboard_utils import ACCENT, MUTED, CARD, BORDER, TEXT

        @app.callback(
            Output(f"{p}-manual-pause", "data"),
            Output(f"{p}-pause-btn", "children"),
            Input(f"{p}-pause-btn", "n_clicks"),
            State(f"{p}-manual-pause", "data"),
            prevent_initial_call=True,
        )
        def toggle_manual_pause(n, cur):
            if not n:
                raise PreventUpdate
            new = not bool(cur)
            label = "▶ Continuă live" if new else "⏸ Pauză live"
            return new, label

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
            Output(f"{p}-applied-filters", "data"),
            Input(f"{p}-search-btn", "n_clicks"),
            State(f"{p}-f-src-ip",   "value"),
            State(f"{p}-f-dst-ip",   "value"),
            State(f"{p}-f-src-port", "value"),
            State(f"{p}-f-dst-port", "value"),
            State(f"{p}-f-min-len",  "value"),
            State(f"{p}-f-max-len",  "value"),
            State(f"{p}-f-proto",    "value"),
            State(f"{p}-f-flags",    "value"),
            State(f"{p}-f-ts-start", "value"),
            State(f"{p}-f-ts-end",   "value"),
        )
        def aplica_filtre(clicks, src_ip, dst_ip, src_port, dst_port, 
                          min_len, max_len, proto, flags, ts_start, ts_end):
            
            # Validări de securitate în backend: dacă datele sunt proaste, oprim execuția
            for val in [src_ip, dst_ip]:
                ok, _ = validate_ip(val, allow_empty=True)
                if not ok: raise PreventUpdate
            for val in [src_port, dst_port]:
                ok, _ = validate_port(val, allow_empty=True)
                if not ok: raise PreventUpdate
                
            ts_min = _parse_ts_input(ts_start)
            ts_max = _parse_ts_input(ts_end)
            has_any_ts = bool((ts_start and str(ts_start).strip()) or (ts_end and str(ts_end).strip()))
            
            if has_any_ts and (ts_min is None or ts_max is None):
                raise PreventUpdate
            if ts_min is not None and ts_max is not None and ts_min > ts_max:
                raise PreventUpdate

            # Salvăm în memorie doar filtrele valide
            return {
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": src_port, "dst_port": dst_port,
                "min_len": min_len, "max_len": max_len,
                "proto": proto, "flags": flags,
                "ts_start": ts_start, "ts_end": ts_end
            }

        # CALLBACK 2: Tabelul live care citește strict din sertar
        @app.callback(
            Output(f"{p}-table", "data"),
            Output(f"{p}-count", "children"),
            Output(f"{p}-last-id", "data"),
            Output(f"{p}-val-msg", "children"),
            Output(f"{p}-freeze-hint", "children"),
            
            # Declanșatori
            Input(f"{p}-interval",   "n_intervals"),
            Input(f"{p}-iface-sel",  "data"),
            Input(f"{p}-manual-pause", "data"),
            Input(f"{p}-applied-filters", "data"),  # Citim direct din sertar
            State(f"{p}-last-id",    "data"),
        )
        def actualizeaza(_, iface_sel, manual_pause, filtre, last_id):
            
            # Extragem valorile din sertar (dacă e gol, setăm None)
            filtre = filtre or {}
            src_ip   = filtre.get("src_ip")
            dst_ip   = filtre.get("dst_ip")
            src_port = filtre.get("src_port")
            dst_port = filtre.get("dst_port")
            min_len  = filtre.get("min_len")
            max_len  = filtre.get("max_len")
            proto    = filtre.get("proto")
            flags    = filtre.get("flags")
            ts_start = filtre.get("ts_start")
            ts_end   = filtre.get("ts_end")

            ts_min = _parse_ts_input(ts_start)
            ts_max = _parse_ts_input(ts_end)

            time_window = ts_min is not None and ts_max is not None
            freeze = bool(manual_pause) or time_window

            ctx = dash.callback_context
            trig = ctx.triggered[0]["prop_id"] if ctx.triggered else ""
            
            if f"{p}-interval" in trig and freeze:
                raise PreventUpdate

            # Orice schimbare în sertar se consideră filtru nou
            este_filtru = "applied-filters" in trig or "manual-pause" in trig

            mgr = self.state.get_manager_interfata(iface_sel)

            def _fetch(min_id_val=None):
                kw = dict(
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    protocol=proto, tcp_flags=flags,
                    min_len=min_len, max_len=max_len,
                    limit=500, min_id=min_id_val,
                    ts_min=ts_min if time_window else None,
                    ts_max=ts_max if time_window else None,
                )
                if mgr:
                    return mgr.get_pachete_filtrate(**kw)
                return self.state.db.get_pachete_filtrate(**kw)

            hint = ""
            if time_window:
                hint = "Interval istoric — fluxul live este oprit până ștergi Start / End."
            elif manual_pause:
                hint = "Pauză manuală — apasă „Continuă live” pentru a relua actualizarea."

            if este_filtru or last_id is None or time_window or ("manual-pause" in trig):
                pachete = _fetch()
                rows = [_format_pachet(pk) for pk in reversed(pachete)]
                new_id = rows[-1]["id"] if rows else None
                if time_window:
                    cnt = f"{len(rows)} pachete (interval)"
                elif manual_pause and "manual-pause" in trig:
                    cnt = f"{len(rows)} pachete (inghetat)"
                else:
                    cnt = f"{len(rows)} pachete afisate"
                return (rows, cnt, new_id, "", hint)

            pachete_noi = _fetch(min_id_val=last_id)
            if not pachete_noi:
                raise PreventUpdate

            new_rows = [_format_pachet(pk) for pk in pachete_noi]
            new_id = new_rows[-1]["id"]
            patched = Patch()
            for row in reversed(new_rows):
                patched.prepend(row)
            return (patched, f"+{len(new_rows)} pachete noi", new_id, "", hint)
