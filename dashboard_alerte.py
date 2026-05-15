import json
import time
from datetime import datetime

import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate

from dashboard_utils import (
    inp, lbl, btn, card, badge_sev,
    style_header_tabel2, style_cell_tabel2,
    SEV_CULORI, ACCENT, MUTED, TEXT, BORDER, CARD, DARK, DARK2,
    get_ip_gazda,
)


SEV_BG = {
    "SCAZUTA": "#86efac18",
    "MEDIE":   "#fde68a18",
    "RIDICATA":"#fb923c18",
    "CRITICA": "#f8717118",
}
SEV_BORDER = SEV_CULORI

TIP_CULORI = {
    "DDoS SYN Flood":         "#a78bfa",   
    "DoS SYN Flood":          "#c084fc",  
    "Port Scan":         "#fb923c",   
    "Brute Force":       "#f87171",  
    "ICMP Flood":        "#fde68a",  
    "DNS Amplification": "#f9a8d4", 
    "Data Exfiltration": "#ff6b6b",
    "Anomalie ML":       "#67e8f9",
    "FIM - FISIER MODIFICAT":      "#fb923c",
    "FIM - FISIER STERS sau MUTAT":"#f87171",
}


def _culoare_alerta(tip_atac: str, severitate: str) -> str:
    return TIP_CULORI.get(tip_atac, SEV_CULORI.get(severitate, MUTED))

TP_BG     = "#052e16"       
TP_BORDER = "#16a34a"       
FP_BG     = "#1c1117"     
FP_BORDER = "#6b4050" 


class SectiuneAlerte:
    DD_STYLE = {"backgroundColor": CARD, "color": DARK, "fontSize": "12px"}

    INTERVAL_OPTS = [
        {"label": "Toate",        "value": "all"},
        {"label": "Ultima ora",   "value": "3600"},
        {"label": "Ultimele 6h",  "value": "21600"},
        {"label": "Ultimele 24h", "value": "86400"},
        {"label": "Ultima sapt.", "value": "604800"},
    ]
    STATUS_OPTS = [
        {"label": "Toate statusurile", "value": "all"},
        {"label": "In asteptare",      "value": "asteptare"},
        {"label": "True Positive",     "value": "tp"},
        {"label": "False Positive",    "value": "fp"},
    ]

    def __init__(self, app_state, prefix: str = "la"):
        self.state = app_state
        self.P     = prefix

    def layout(self):
        p = self.P
        scan_pasiv = html.Div([
            html.P(
                "Ruleaza detectorii built-in si regulile custom din baza live "
                "pe pachetele din captura incarcata (moment de referinta = sfarsitul capturii).",
                style={"fontSize": "12px", "color": MUTED,
                       "margin": "0 0 12px 0", "lineHeight": "1.5"},
            ),
            dcc.Loading(
                id="pa-scan-loading",
                type="circle",
                color="#38bdf8",
                fullscreen=False,
                style={"minHeight": "48px"},
                children=html.Div([
                    html.Button(
                        "🔍 Scan reguli pe captura",
                        id="p-scan-db-btn",
                        n_clicks=0,
                        style={
                            "background": "#1e40af",
                            "color": "#93c5fd",
                            "border": "none",
                            "borderRadius": "8px",
                            "padding": "10px 20px",
                            "cursor": "pointer",
                            "fontSize": "13px",
                            "fontWeight": "600",
                        },
                    ),
                    html.Div(id="p-scan-msg",
                             style={"fontSize": "12px", "color": MUTED,
                                    "marginTop": "10px"}),
                ]),
            ),
        ], style={
            "marginBottom": "16px",
            "padding": "14px 16px",
            "borderRadius": "10px",
            "border": f"1px solid {BORDER}",
            "backgroundColor": "rgba(30,58,138,0.12)",
        }) if p == "pa" else html.Div()

        return html.Div([
            scan_pasiv,
            card([
                html.Div([
                    html.Div([html.Label("Interval:", style=lbl()),
                              dcc.Dropdown(id=f"{p}-f-interval",
                                           options=self.INTERVAL_OPTS,
                                           value="all", clearable=False,
                                           style={**self.DD_STYLE,
                                                  "width": "140px"})]),
                    html.Div([html.Label("Status:", style=lbl()),
                              dcc.Dropdown(id=f"{p}-f-status",
                                           options=self.STATUS_OPTS,
                                           value="all", clearable=False,
                                           style={**self.DD_STYLE,
                                                  "width": "155px"})]),
                    html.Div([html.Label("Severitate:", style=lbl()),
                              dcc.Dropdown(id=f"{p}-f-sev",
                                options=[{"label":"Toate","value":"all"},
                                         {"label":"CRITICA","value":"CRITICA"},
                                         {"label":"RIDICATA","value":"RIDICATA"},
                                         {"label":"MEDIE","value":"MEDIE"},
                                         {"label":"SCAZUTA","value":"SCAZUTA"}],
                                value="all", clearable=False,
                                style={**self.DD_STYLE, "width": "135px"})]),
                    html.Div([html.Label("Tip atac:", style=lbl()),
                              dcc.Dropdown(id=f"{p}-f-tip",
                                           options=[{"label":"Toate","value":"all"}],
                                           value="all", clearable=False,
                                           style={**self.DD_STYLE,
                                                  "width": "190px"})]),
                    html.Div([html.Label("Cauta IP:", style=lbl()),
                              dcc.Input(id=f"{p}-f-ip", type="text",
                                        placeholder="filtreaza dupa IP",
                                        debounce=True,
                                        style=inp({"width": "145px",
                                                   "fontSize": "12px"}))]),
                    html.Div([html.Label("Tara:", style=lbl()),
                              dcc.Dropdown(id=f"{p}-f-country",
                                           options=[{"label":"Toate","value":"all"}],
                                           value="all", clearable=False,
                                           style={**self.DD_STYLE, "width": "130px"})]),
                    html.Div([html.Label("Proces local:", style=lbl()),
                              dcc.Input(id=f"{p}-f-proc", type="text",
                                        placeholder="ex: powershell",
                                        debounce=True,
                                        style=inp({"width": "145px",
                                                   "fontSize": "12px"}))]),
                    html.Div([html.Label("ASN/Organizatie:", style=lbl()),
                              dcc.Input(id=f"{p}-f-asn", type="text",
                                        placeholder="ex: Cloudflare",
                                        debounce=True,
                                        style=inp({"width": "160px",
                                                   "fontSize": "12px"}))]),
                    html.Div([html.Label("Port scanat:", style=lbl()),
                              dcc.Input(id=f"{p}-f-portscan", type="text",
                                        placeholder="ex: 80",
                                        debounce=True,
                                        style=inp({"width": "110px",
                                                   "fontSize": "12px"}))]),
                    html.Div([
                        dcc.Checklist(
                            id=f"{p}-f-ext-only",
                            options=[{"label": "Doar extern", "value": "on"}],
                            value=[],
                            style={"color": TEXT, "fontSize": "12px",
                                   "paddingBottom": "6px"},
                            labelStyle={"display": "inline-flex", "gap": "6px"},
                        )
                    ], style={"alignSelf": "flex-end"}),
                    html.Button("Cauta", id=f"{p}-search-btn", n_clicks=0,
                                style={"alignSelf": "flex-end",
                                       "background": "#1e40af",
                                       "color": "#93c5fd",
                                       "border": "none", "borderRadius": "6px",
                                       "padding": "6px 12px", "cursor": "pointer"}),
                    html.Span(id=f"{p}-count",
                              style={"alignSelf": "flex-end",
                                     "fontSize": "11px",
                                     "color": MUTED,
                                     "paddingBottom": "6px"}),
                ], style={"display": "flex", "gap": "8px",
                          "flexWrap": "wrap", "alignItems": "flex-end"}),
            ], {"padding": "10px 14px", "marginBottom": "10px"}),

            html.Div(id=f"{p}-container",
                     style={"maxHeight": "680px", "overflowY": "auto",
                            "paddingRight": "2px"}),

            dcc.Interval(id=f"{p}-interval",      interval=4000, n_intervals=0),
            dcc.Store(id=f"{p}-open-id",           data=None),
            dcc.Store(id=f"{p}-tp-fp-store",       data=0),
            dcc.Store(id=f"{p}-seen-store",        data=0),
            dcc.Store(id=f"{p}-last-alert-id",     data=None),
        ])

    def register_callbacks(self, app):
        p = self.P

        @app.callback(
            Output(f"{p}-f-tip", "options"),
            Input(f"{p}-interval", "n_intervals"),
        )
        def refresh_tipuri(_):
            alerte = self.state.db.get_alerte(limit=1000)
            tipuri = sorted({a["tip_atac"] for a in alerte if a["tip_atac"]})
            return [{"label": "Toate tipurile", "value": "all"}] + \
                   [{"label": t, "value": t} for t in tipuri]

        @app.callback(
            Output(f"{p}-f-country", "options"),
            Input(f"{p}-interval", "n_intervals"),
        )
        def refresh_tari(_):
            tari = self.state.db.get_tari_alerte(limit=200)
            return [{"label": "Toate", "value": "all"}] + [
                {"label": c, "value": c} for c in tari
            ]

        @app.callback(
            Output(f"{p}-open-id", "data"),
            Input({"type": f"{p}-btn-det",
                   "index": dash.dependencies.ALL}, "n_clicks"),
            State(f"{p}-open-id", "data"),
            prevent_initial_call=True,
        )
        def toggle_detalii(clicks, current):
            ctx = dash.callback_context
            if not ctx.triggered or not any(c for c in clicks if c):
                raise PreventUpdate
            try:
                info    = json.loads(ctx.triggered[0]["prop_id"].split(".")[0])
                clicked = info["index"]
                return None if current == clicked else clicked
            except Exception:
                raise PreventUpdate

        @app.callback(
            Output(f"{p}-seen-store", "data"),
            Input({"type": f"{p}-chk-seen",
                   "index": dash.dependencies.ALL}, "value"),
            State(f"{p}-seen-store", "data"),
            prevent_initial_call=True,
        )
        def toggle_vazut(_, counter):
            ctx = dash.callback_context
            if not ctx.triggered:
                raise PreventUpdate
            prop = ctx.triggered[0]["prop_id"]
            try:
                id_payload = prop.split(".")[0]
                value_payload = ctx.triggered[0].get("value") or []
                info = json.loads(id_payload)
                alerta_id = int(info["index"])
                este_vazuta = "seen" in value_payload
                self.state.db.update_vazut_alerta(alerta_id, este_vazuta)
            except Exception:
                raise PreventUpdate
            return (counter or 0) + 1

        @app.callback(
            Output(f"{p}-tp-fp-store", "data"),
            Input({"type": f"{p}-btn-tp",
                   "index": dash.dependencies.ALL}, "n_clicks"),
            Input({"type": f"{p}-btn-fp",
                   "index": dash.dependencies.ALL}, "n_clicks"),
            State(f"{p}-tp-fp-store", "data"),
            prevent_initial_call=True,
        )
        def confirma(tp_clicks, fp_clicks, counter):
            ctx = dash.callback_context
            if not ctx.triggered:
                raise PreventUpdate
            if not any(c for c in (tp_clicks + fp_clicks) if c):
                raise PreventUpdate
            prop = ctx.triggered[0]["prop_id"]
            try:
                info    = json.loads(prop.split(".")[0])
                valoare = 1 if info["type"] == f"{p}-btn-tp" else 0
                self.state.db.update_confirmare_alerta(info["index"], valoare)
            except Exception:
                pass
            return (counter or 0) + 1

        @app.callback(
            Output(f"{p}-container", "children"),
            Output(f"{p}-count",     "children"),
            Input(f"{p}-interval",    "n_intervals"),
            Input(f"{p}-search-btn",  "n_clicks"),
            Input(f"{p}-tp-fp-store", "data"),
            Input(f"{p}-seen-store",  "data"),
            Input("pa-scan-tick",     "data"),
            State(f"{p}-open-id",     "data"),
            State(f"{p}-f-interval",  "value"),
            State(f"{p}-f-status",    "value"),
            State(f"{p}-f-sev",       "value"),
            State(f"{p}-f-tip",       "value"),
            State(f"{p}-f-ip",        "value"),
            State(f"{p}-f-country",   "value"),
            State(f"{p}-f-proc",      "value"),
            State(f"{p}-f-asn",       "value"),
            State(f"{p}-f-ext-only",  "value"),
            State(f"{p}-f-portscan",  "value"),
        )
        def randeaza(_, _search, _tpfp, _seen, _scan, 
                     open_id, interval_val, status_val, sev_val, tip_val, ip_val,
                     country_val, proc_val, asn_val, ext_only_val, portscan_val):
            
            ts_start = None
            if interval_val and interval_val != "all":
                try:
                    ts_start = time.time() - int(interval_val)
                except Exception:
                    pass

            alerte = self.state.db.get_alerte(
                limit=200, ts_start=ts_start,
                severitate=sev_val,
                tip_atac=tip_val,
                confirmat_filter=status_val if status_val != "all" else None,
                ip_filter=ip_val,
                country_filter=country_val,
                asn_org_filter=asn_val,
                process_filter=proc_val,
                external_only=("on" in (ext_only_val or [])))

            carduri = []
            for a in alerte:
                sev       = a.get("severitate", "MEDIE")
                culoare   = _culoare_alerta(a.get("tip_atac", ""), sev)
                confirmat = a.get("confirmat")
                deschis   = (open_id == a["id"])
                vazuta    = bool(a.get("vazut", 0))
                ora       = datetime.fromtimestamp(
                                a["timestamp"]).strftime("%d.%m %H:%M:%S")

                if confirmat == 1:          
                    bg_card     = TP_BG
                    border_left = TP_BORDER
                    border_rest = f"1px solid {TP_BORDER}55"
                elif confirmat == 0:       
                    bg_card     = FP_BG
                    border_left = FP_BORDER
                    border_rest = f"1px solid {FP_BORDER}55"
                else: 
                    bg_card     = SEV_BG.get(sev, "#ffffff08")
                    border_left = culoare
                    border_rest = f"1px solid {culoare}30"

                if confirmat == 1:
                    stare_el = html.Span("✓ TP", style={
                        "color": "#86efac", "fontSize": "11px",
                        "fontWeight": "700", "marginLeft": "6px",
                        "backgroundColor": "#166534",
                        "padding": "2px 6px", "borderRadius": "4px"})
                elif confirmat == 0:
                    stare_el = html.Span("✗ FP", style={
                        "color": "#d4a0a0", "fontSize": "11px",
                        "fontWeight": "700", "marginLeft": "6px",
                        "backgroundColor": "#3d1a1a",
                        "padding": "2px 6px", "borderRadius": "4px"})
                else:
                    stare_el = html.Div([
                        html.Button("✓ TP",
                            id={"type": f"{p}-btn-tp", "index": a["id"]},
                            n_clicks=0,
                            style={"background": "#166534",
                                   "color": "#86efac",
                                   "border": "none", "borderRadius": "3px",
                                   "padding": "2px 7px", "cursor": "pointer",
                                   "fontSize": "11px", "fontWeight": "700",
                                   "marginLeft": "6px"}),
                        html.Button("✗ FP",
                            id={"type": f"{p}-btn-fp", "index": a["id"]},
                            n_clicks=0,
                            style={"background": "#3d1a1a",
                                   "color": "#d4a0a0",
                                   "border": "none", "borderRadius": "3px",
                                   "padding": "2px 7px", "cursor": "pointer",
                                   "fontSize": "11px", "fontWeight": "700",
                                   "marginLeft": "4px"}),
                    ], style={"display": "inline-flex",
                              "alignItems": "center"})

                badge_vazuta = (
                    html.Span(
                        "Vazuta",
                        style={
                            "fontSize": "9px",
                            "color": "#64748b",
                            "fontWeight": "700",
                            "marginRight": "8px",
                            "textTransform": "uppercase",
                            "letterSpacing": "0.08em",
                            "border": "1px solid #334155",
                            "borderRadius": "4px",
                            "padding": "2px 5px",
                        },
                    )
                    if vazuta else None
                )

                detalii_panel = self._detalii(a, portscan_val) if deschis else []

                card_stil_card = {
                    "backgroundColor": bg_card,
                    "borderRadius": "8px",
                    "padding": "8px 12px",
                    "marginBottom": "6px",
                    "borderLeft":   f"4px solid {border_left}",
                    "borderTop":    border_rest,
                    "borderRight":  border_rest,
                    "borderBottom": border_rest,
                }
                if vazuta:
                    card_stil_card.update({
                        "opacity": "0.5",
                        "filter": "grayscale(0.55)",
                        "boxShadow": "none",
                    })

                rand_dreapta = [
                    html.Span(ora, style={"color": MUTED,
                                          "fontSize": "11px",
                                          "marginRight": "8px",
                                          "whiteSpace": "nowrap"}),
                    dcc.Checklist(
                        id={"type": f"{p}-chk-seen", "index": a["id"]},
                        options=[{"label": "Vazut", "value": "seen"}],
                        value=["seen"] if vazuta else [],
                        style={"color": TEXT, "fontSize": "11px",
                               "marginRight": "8px"},
                        labelStyle={"display": "inline-flex",
                                    "alignItems": "center", "gap": "4px"},
                        inputStyle={"marginRight": "4px"},
                    ),
                ]
                if badge_vazuta is not None:
                    rand_dreapta.append(badge_vazuta)

                rand_dreapta.extend([
                    stare_el,
                    html.Button(
                        "▲" if deschis else "▼",
                        id={"type": f"{p}-btn-det", "index": a["id"]},
                        n_clicks=0,
                        style={"background": "transparent",
                               "color": culoare,
                               "border": f"1px solid {culoare}55",
                               "borderRadius": "3px",
                               "padding": "1px 7px",
                               "cursor": "pointer",
                               "fontSize": "12px",
                               "marginLeft": "8px"}),
                ])

                carduri.append(html.Div([
                    html.Div([
                        html.Div([
                            html.Span(a["tip_atac"],
                                      style={"fontWeight": "700",
                                             "color": culoare,
                                             "fontSize": "13px",
                                             "marginRight": "6px"}),
                            html.Span(sev, style={
                                "backgroundColor": culoare + "28",
                                "color": culoare,
                                "border": f"1px solid {culoare}55",
                                "borderRadius": "3px",
                                "padding": "1px 5px",
                                "fontSize": "10px",
                                "fontWeight": "700",
                                "marginRight": "10px"}),
                            html.Span(
                                f"src: {a['src_ip'] or '-'}  →  "
                                f"dst: {a['dst_ip'] or '-'}",
                                style={"color": MUTED, "fontSize": "11px",
                                       "fontFamily": "monospace"}),
                        ], style={"display": "flex", "alignItems": "center",
                                  "flex": "1", "minWidth": "0",
                                  "overflow": "hidden"}),

                        html.Div(rand_dreapta, style={"display": "flex",
                                                      "alignItems": "center",
                                                      "flexShrink": "0"}),
                    ], style={"display": "flex", "alignItems": "center",
                              "justifyContent": "space-between"}),

                    # Detalii scurte (trunchiate, cand card e inchis)
                    html.Div(
                        (a.get("detalii") or "")[:90] +
                        ("…" if len(a.get("detalii") or "") > 90 else ""),
                        style={"color": TEXT, "fontSize": "11px",
                               "marginTop": "3px",
                               "fontFamily": "monospace",
                               "opacity": "0.75"}
                    ) if not deschis else html.Div(),

                    *detalii_panel,

                ], style=card_stil_card))

            if not carduri:
                carduri = [html.P(
                    "Nicio alerta pentru filtrele selectate.",
                    style={"color": MUTED, "textAlign": "center",
                           "padding": "40px"})]

            return carduri, f"{len(alerte)} alerte"

        if p == "pa":
            @app.callback(
                Output("p-scan-msg", "children"),
                Output("pa-scan-tick", "data"),
                Input("p-scan-db-btn", "n_clicks"),
                State("pa-scan-tick", "data"),
                prevent_initial_call=True,
            )
            def scan_pasiv_db(_, tick):
                _ok, msg = self.state.scan_reguli_pe_captura_pasiva(get_ip_gazda())
                return msg, (tick or 0) + 1

    def _detalii(self, a: dict, portscan_filter: str = None) -> list:
        tip     = (a["tip_atac"] or "").upper()
        sev     = a.get("severitate", "MEDIE")
        culoare = _culoare_alerta(a.get("tip_atac", ""), sev)
        confirmat = a.get("confirmat")

        if confirmat == 1:
            separator_color = TP_BORDER
        elif confirmat == 0:
            separator_color = FP_BORDER
        else:
            separator_color = _culoare_alerta(a.get("tip_atac", ""), sev)

        info = html.Div([
            html.Div([
                html.Div([
                    html.Span("IP Sursa: ",
                              style={"color": MUTED, "fontSize": "11px"}),
                    html.Span(a["src_ip"] or "-",
                              style={"color": "#7dd3fc", "fontSize": "11px",
                                     "fontFamily": "monospace",
                                     "marginRight": "20px"}),
                    html.Span("IP Destinatie: ",
                              style={"color": MUTED, "fontSize": "11px"}),
                    html.Span(a["dst_ip"] or "-",
                              style={"color": "#7dd3fc", "fontSize": "11px",
                                     "fontFamily": "monospace",
                                     "marginRight": "20px"}),
                    html.Span("Sursa detectie: ",
                              style={"color": MUTED, "fontSize": "11px"}),
                    html.Span(a["sursa"] or "-",
                              style={"color": TEXT, "fontSize": "11px"}),
                ]),
            ], style={"marginBottom": "6px"}),
            self._context_block(a),
            html.Div(a.get("detalii", ""),
                     style={"color": TEXT, "fontSize": "11px",
                            "fontFamily": "monospace",
                            "backgroundColor": "#0f172a55",
                            "borderRadius": "4px",
                            "padding": "6px 10px",
                            "whiteSpace": "pre-wrap",
                            "wordBreak": "break-all"}),
        ], style={"marginBottom": "8px"})

        tabel_specific = []

        if "PORT SCAN" in tip and a.get("src_ip"):
            porturi = self.state.db.get_porturi_scanate(
                a["src_ip"], a["timestamp"] - 120, a["timestamp"] + 120)
            if portscan_filter and str(portscan_filter).strip():
                port_q = str(portscan_filter).strip()
                porturi = [r for r in porturi if str(r.get("dst_port")) == port_q]
            if porturi:
                rows = [{
                    "dst_ip":    r["dst_ip"] or "-",
                    "dst_port":  r["dst_port"],
                    "tentative": r["tentative"],
                    "prima_ora": datetime.fromtimestamp(
                        r["prima_ora"]).strftime("%H:%M:%S"),
                    "ultima_ora": datetime.fromtimestamp(
                        r["ultima_ora"]).strftime("%H:%M:%S"),
                } for r in porturi]
                tabel_specific = [
                    html.P(f"{len(porturi)} porturi scanate de {a['src_ip']}:",
                           style={"color": TEXT, "fontSize": "11px",
                                  "fontWeight": "600",
                                  "margin": "8px 0 4px 0"}),
                    dash_table.DataTable(
                        columns=[{"name": n, "id": i} for n, i in [
                            ("IP Tinta", "dst_ip"), ("Port", "dst_port"),
                            ("Tentative", "tentative"),
                            ("Prima ora", "prima_ora"),
                            ("Ultima ora", "ultima_ora")]],
                        data=rows, page_size=12, sort_action="native",
                        style_header=style_header_tabel2(),
                        style_cell=style_cell_tabel2(),
                        style_table={"overflowX": "auto",
                                     "maxHeight": "200px",
                                     "overflowY": "auto"}),
                ]

        elif ("BRUTE" in tip or "FORCE" in tip) \
                and a.get("src_ip") and a.get("dst_ip"):
            tent = self.state.db.get_tentative_autentificare(
                a["src_ip"], a["dst_ip"],
                a["timestamp"] - 120, a["timestamp"] + 120)
            if tent:
                rows = [{
                    "ora":   datetime.fromtimestamp(
                             t["timestamp"]).strftime("%H:%M:%S"),
                    "port":  t["dst_port"],
                    "flags": t["tcp_flags"] or "-",
                    "bytes": t["packet_len"],
                } for t in tent]
                tabel_specific = [
                    html.P(f"{len(tent)} tentative "
                           f"{a['src_ip']} → {a['dst_ip']}:",
                           style={"color": TEXT, "fontSize": "11px",
                                  "fontWeight": "600",
                                  "margin": "8px 0 4px 0"}),
                    dash_table.DataTable(
                        columns=[{"name": n, "id": i} for n, i in [
                            ("Ora", "ora"), ("Port", "port"),
                            ("Flags", "flags"), ("Bytes", "bytes")]],
                        data=rows, page_size=12, sort_action="native",
                        style_header=style_header_tabel2(),
                        style_cell=style_cell_tabel2(),
                        style_table={"overflowX": "auto",
                                     "maxHeight": "200px",
                                     "overflowY": "auto"}),
                ]

        return [html.Div(
            [info, *tabel_specific],
            style={"borderTop": f"1px solid {separator_color}40",
                   "marginTop": "6px", "paddingTop": "8px"})]

    def _context_block(self, alerta: dict):
        ctx = alerta.get("context") or {}
        src_geo = ctx.get("src_geo") or {}
        dst_geo = ctx.get("dst_geo") or {}
        proc = ctx.get("local_process") or {}

        if not src_geo and any([alerta.get("src_country"), alerta.get("src_asn")]):
            src_geo = {
                "country": alerta.get("src_country"),
                "asn": alerta.get("src_asn"),
            }
        if not dst_geo and any([alerta.get("dst_country"), alerta.get("dst_asn")]):
            dst_geo = {
                "country": alerta.get("dst_country"),
                "asn": alerta.get("dst_asn"),
            }

        src_geo_txt = ", ".join(filter(None, [
            src_geo.get("country"), src_geo.get("city"),
            f"AS{src_geo.get('asn')}" if src_geo.get("asn") else None,
            src_geo.get("org"),
        ])) or "-"
        dst_geo_txt = ", ".join(filter(None, [
            dst_geo.get("country"), dst_geo.get("city"),
            f"AS{dst_geo.get('asn')}" if dst_geo.get("asn") else None,
            dst_geo.get("org"),
        ])) or "-"
        proc_txt = "-"
        if proc:
            proc_txt = " | ".join(filter(None, [
                proc.get("name"),
                f"ID proces {proc.get('pid')}" if proc.get("pid") else None,
                proc.get("exe"),
            ]))

        parts = [
            ctx.get("src_domain"), ctx.get("dst_domain"),
            src_geo_txt if src_geo_txt != "-" else None,
            dst_geo_txt if dst_geo_txt != "-" else None,
            proc_txt if proc_txt != "-" else None
        ]
        status = "partial" if any(parts) else "none"
        status_color = "#fde68a" if status == "partial" else "#94a3b8"
        status_text = "context imbogatit partial" if status == "partial" else "context indisponibil"

        return html.Div([
            html.Span("Context", style={"color": ACCENT, "fontWeight": "700",
                                        "fontSize": "11px", "marginRight": "8px"}),
            html.Span(status_text, style={"color": status_color, "fontSize": "10px",
                                          "fontWeight": "700", "marginLeft": "6px"}),
            html.Div([
                html.Div(f"domeniu sursa: {ctx.get('src_domain') or '-'}",
                         style={"fontSize": "11px", "color": TEXT}),
                html.Div(f"domeniu destinatie: {ctx.get('dst_domain') or '-'}",
                         style={"fontSize": "11px", "color": TEXT}),
                html.Div(f"geolocatie/asn sursa: {src_geo_txt}",
                         style={"fontSize": "11px", "color": TEXT}),
                html.Div(f"geolocatie/asn destinatie: {dst_geo_txt}",
                         style={"fontSize": "11px", "color": TEXT}),
                html.Div(f"proces local: {proc_txt}",
                         style={"fontSize": "11px", "color": TEXT}),
            ], style={"fontFamily": "monospace", "lineHeight": "1.5"}),
        ], style={"marginBottom": "8px", "padding": "6px 10px",
                  "borderRadius": "4px", "backgroundColor": "#0b122255",
                  "border": f"1px solid {BORDER}"})