import json
import os

import dash
from dash import dcc, html
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate

from dashboard_utils import (
    inp, lbl, btn, card, badge_sev, sectiune_titlu,
    ACCENT, MUTED, TEXT, BORDER, CARD, DARK,
)
from validators import validate_port, validate_tcp_flags, validate_rule_name


DETECTORI_META = {
    "Port Scan": {
        "descriere": (
            "Detecteaza un IP care incearca sa descopere servicii active "
            "pe retea prin conectarea rapida la multe porturi diferite. "
            "Tehnica comuna in faza de recunoastere a unui atac."
        ),
        "params": {
            "prag":      "Porturi distincte contactate (declansare alerta)",
            "fereastra": "Fereastra de timp analizata (secunde)",
        },
    },
    "DDoS SYN Flood": {
        "descriere": (
            "Atac DoS/DDoS: un numar mare de pachete SYN sunt trimise catre "
            "un singur server, epuizand resursele acestuia fara a finaliza "
            "conexiunile TCP (half-open connections)."
        ),
        "params": {
            "prag_syn":   "Pachete SYN catre acelasi ip:port (declansare)",
            "prag_surse": "Surse IP distincte implicate (minim)",
            "fereastra":  "Fereastra de timp analizata (secunde)",
        },
    },
    "Brute Force": {
        "descriere": (
            "Detecteaza incercari repetate de autentificare de la acelasi IP "
            "catre servicii expuse: SSH (22), RDP (3389), FTP (21), Telnet (23). "
            "Indica o incercare de a ghici parole prin forta bruta."
        ),
        "params": {
            "prag":      "Tentative de conexiune de la acelasi IP pe acelasi port",
            "fereastra": "Fereastra de timp analizata (secunde)",
        },
    },
    "DNS Amplification": {
        "descriere": (
            "Atac DDoS prin reflexie: atacatorul trimite cereri DNS mici catre "
            "servere publice (spoofand IP-ul victimei), care raspund cu mesaje "
            "mult mai mari, amplificand traficul catre tinta."
        ),
        "params": {
            "prag_ratio":  "Raport amplificare raspuns/cerere DNS (de X ori)",
            "prag_volum":  "Raspunsuri DNS primite in fereastra (minim)",
            "fereastra":   "Fereastra de timp analizata (secunde)",
        },
    },
    "Data Exfiltration": {
        "descriere": (
            "Beaconing catre un IP exterior: volum mare + multe octeti si un ritm intre pachete lent in mediu "
            "si foarte regulat (nu rafala de browser/CDN). Prag_med_min filtreaza fluxurile cu interval mediu "
            "aproape zero. Alerta daca deviatia intervalelor (std) e sub prag_std — prag_std mic ⇒ doar ritm "
            "aproape perfect periodic."
        ),
        "params": {
            "prag_pachete": "Minim pachete spre acel IP (implicit foarte mare)",
            "prag_std": ("Deviatie std a gap-urilor (s); alerta doar daca std < prag "
                         "(mai mic ⇒ doar puls extrem de regulat)"),
            "prag_bytes":   "Bytes minim catre IP in fereastra (~8 MiB implicit)",
            "prag_med_min": "Interval mediu min. intre pachete catre tinta (s); sub → ignora (rafala)",
            "fereastra":    "Fereastra de timp (secunde)",
        },
    },
    "ICMP Flood": {
        "descriere": (
            "Atac DoS prin inundarea tintei cu pachete ICMP (ping flood). "
            "Consuma latimea de banda si resursele CPU ale victimei. "
            "Poate fi folosit si pentru recunoasterea retelei."
        ),
        "params": {
            "prag":      "Pachete ICMP de la acelasi IP sursa (declansare)",
            "fereastra": "Fereastra de timp analizata (secunde)",
        },
    },
    "Anomalie ML": {
        "descriere": (
            "Model Isolation Forest antrenat pe trafic normal. Detecteaza "
            "comportamente statistice anormale fara reguli predefinite — "
            "util pentru atacuri noi sau necunoscute (zero-day)."
        ),
        "params": {
            "fereastra": "Fereastra de agregare features (secunde)",
        },
    },
}


def _btn_ml(label: str, bg: str, fg: str,
            enabled: bool, btn_id: dict, extra: dict = None) -> html.Button:
    if enabled:
        stil = {
            "background": bg, "color": fg, "border": "none",
            "borderRadius": "6px", "padding": "7px 16px",
            "cursor": "pointer", "fontSize": "12px", "fontWeight": "600",
            "minWidth": "160px", "transition": "opacity .15s",
        }
    else:
        stil = {
            "background": "#1e293b", "color": "#475569", "border": "none",
            "borderRadius": "6px", "padding": "7px 16px",
            "cursor": "not-allowed", "fontSize": "12px", "fontWeight": "600",
            "minWidth": "160px", "opacity": "0.55",
        }
    if extra:
        stil.update(extra)
    return html.Button(label, id=btn_id, n_clicks=0,
                       disabled=not enabled, style=stil)


def _subcard(continut, accent_color: str = ACCENT):
    return html.Div(continut, style={
        "backgroundColor": f"{accent_color}08",
        "border": f"1px solid {accent_color}22",
        "borderLeft": f"3px solid {accent_color}",
        "borderRadius": "8px",
        "padding": "16px",
        "marginBottom": "10px",
    })


class SectiuneSetari:
    DD_STYLE = {"backgroundColor": DARK, "color": TEXT, "fontSize": "13px"}

    def __init__(self, app_state, prefix: str = "ls"):
        self.state = app_state
        self.P     = prefix

    def layout(self):
        p = self.P
        return html.Div([

            html.H3("Model Anomalii ML",
                    style={"color": TEXT, "fontSize": "15px",
                           "marginBottom": "10px"}),
            card([
                _subcard([
                    html.Div([
                        html.Span("Antrenare model",
                                  style={"color": ACCENT, "fontWeight": "700",
                                         "fontSize": "14px"}),
                        html.Span(id=f"{p}-ml-status-badge",
                                  style={"marginLeft": "10px"}),
                    ], style={"marginBottom": "10px"}),

                    html.P(
                        "Antreneaza modelul Isolation Forest pe date istorice "
                        "de trafic normal. Modelul va detecta automat "
                        "comportamente anormale (zero-day) fara reguli fixe.",
                        style={"color": MUTED, "fontSize": "12px",
                               "margin": "0 0 14px 0", "lineHeight": "1.6"}),

                    html.Div([
                        html.Label("Sursa date antrenare:", style=lbl()),
                        dcc.RadioItems(
                            id=f"{p}-ml-sursa",
                            options=[
                                {"label": "  Trafic live (DB curent)",
                                 "value": "live"},
                                {"label": "  Fisier .db extern",
                                 "value": "extern"},
                            ],
                            value="live",
                            labelStyle={"marginRight": "18px",
                                        "fontSize": "12px", "color": TEXT},
                            style={"display": "flex", "flexWrap": "wrap"}),
                    ], style={"marginBottom": "10px"}),

                    html.Div(id=f"{p}-ml-extern-row", children=[
                        html.Div([
                            html.Div(id=f"{p}-ml-extern-cale",
                                     children="Niciun fisier selectat",
                                     style={"flex": "1", "color": MUTED,
                                            "fontSize": "12px",
                                            "fontFamily": "monospace",
                                            "padding": "5px 10px",
                                            "backgroundColor": DARK,
                                            "borderRadius": "6px",
                                            "border": f"1px solid {BORDER}",
                                            "marginRight": "8px"}),
                            html.Button("📂 Browse",
                                        id=f"{p}-ml-browse",
                                        style={**btn("#1e40af", "#93c5fd"),
                                               "fontSize": "12px"}),
                        ], style={"display": "flex", "alignItems": "center",
                                  "marginBottom": "10px"}),
                        dcc.Store(id=f"{p}-ml-extern-store"),
                    ], style={"display": "none"}),

                    html.Div([
                        html.Label("Date de antrenare (ore):", style=lbl()),
                        dcc.Input(id=f"{p}-ml-ore", type="number",
                                  value=24, min=1, max=720,
                                  style=inp({"width": "80px",
                                             "fontSize": "12px",
                                             "padding": "4px 8px"})),
                    ], style={"marginBottom": "14px"}),

                    html.Div(id=f"{p}-ml-btns",
                             style={"display": "flex", "gap": "10px",
                                    "flexWrap": "wrap"}),

                    html.Div(id=f"{p}-ml-msg",
                             style={"marginTop": "8px", "fontSize": "12px",
                                    "color": "#86efac"}),
                ], accent_color=ACCENT),

                _subcard([
                    html.Span("Detectie anomalii ML",
                              style={"color": "#7dd3fc", "fontWeight": "700",
                                     "fontSize": "14px"}),
                    html.P(
                        "Cand detectia e activa, modelul (daca e antrenat) "
                        "analizeaza traficul la fiecare ciclu de detectie "
                        "si emite alerte pentru comportamente anormale.",
                        style={"color": MUTED, "fontSize": "12px",
                               "margin": "8px 0 12px 0",
                               "lineHeight": "1.6"}),
                    html.Div(id=f"{p}-det-toggle-area",
                             style={"display": "flex", "alignItems": "center",
                                    "gap": "12px"}),
                ], accent_color="#7dd3fc"),

            ]),

            html.Div(style={"height": "8px"}),

            html.H3("Parametrii detectori",
                    style={"color": TEXT, "fontSize": "15px",
                           "marginBottom": "12px", "marginTop": "4px"}),
            card([
                html.P(
                    "Modifica valorile de declansare pentru fiecare detector. "
                    "Valori mai mici = detectie mai agresiva (mai multe alerte). "
                    "Valori mai mari = mai putine false positive. "
                    "Modificarile sunt aplicate la urmatoarea rulare.",
                    style={"color": MUTED, "fontSize": "12px",
                           "margin": "0 0 16px 0", "lineHeight": "1.6"}),
                html.Div(id=f"{p}-detectori-lista"),
                dcc.Store(id=f"{p}-det-save-store", data=0),
            ]),

            html.Div(style={"height": "8px"}),

            html.H3("Reguli de detectie custom",
                    style={"color": TEXT, "fontSize": "15px",
                           "marginBottom": "10px", "marginTop": "4px"}),
            card([
                sectiune_titlu("Adauga regula noua"),
                html.Div([
                    dcc.Input(id=f"{p}-r-nume", type="text",
                              placeholder="Nume regula",
                              style=inp({"width": "165px"})),
                    dcc.Dropdown(id=f"{p}-r-protocol",
                        options=[{"label": x, "value": x}
                                 for x in ["all","TCP","UDP","OTHER"]],
                        value="TCP",
                        style={**self.DD_STYLE, "width": "95px"}),
                    dcc.Input(id=f"{p}-r-port", type="text",
                              placeholder="Port (opt.)",
                              style=inp({"width": "95px"})),
                    dcc.Input(id=f"{p}-r-flags", type="text",
                              placeholder="Flags",
                              style=inp({"width": "85px"})),
                    dcc.Input(id=f"{p}-r-prag", type="number",
                              placeholder="Prag", 
                              style=inp({"width": "75px"})),
                    dcc.Input(id=f"{p}-r-fereastra", type="number",
                              placeholder="Secunde", 
                              style=inp({"width": "85px"})),
                    dcc.Dropdown(id=f"{p}-r-sev",
                        options=[{"label": x, "value": x}
                                 for x in ["SCAZUTA","MEDIE","RIDICATA","CRITICA"]],
                        value="MEDIE",
                        style={**self.DD_STYLE, "width": "115px"}),
                    html.Button("+ Adauga", id=f"{p}-r-add",
                                style=btn("#166534", "white")),
                ], style={"display": "flex", "gap": "8px",
                          "flexWrap": "wrap", "alignItems": "center",
                          "marginBottom": "10px"}),
                html.Div(id=f"{p}-r-add-status",
                         style={"fontSize": "12px", "color": "#86efac"}),
                html.Div(id=f"{p}-r-add-help",
                         style={"fontSize": "11px", "color": MUTED,
                                "marginTop": "6px"}),
                html.Div(
                    "Format: nume 3-64 caractere | port 1-65535 | flags TCP: S,A,F,R,P,U",
                    style={"fontSize": "11px", "color": MUTED, "marginTop": "4px"},
                ),
            ]),

            html.Div(id=f"{p}-r-lista"),

            html.Div(style={"height": "14px"}),

            html.H3("Monitorizare integritate fisiere (FIM)",
                    style={"color": TEXT, "fontSize": "15px",
                           "marginBottom": "10px", "marginTop": "4px"}),
            card([
                sectiune_titlu("Cai suplimentare"),
                html.P(
                    "Pe langa fisierele implicite (ex. hosts), poti adauga cai "
                    "complete catre fisiere monitorizate. Modificarile fata de "
                    "baseline genereaza alerte FIM. Lista salvata in baza SQLite.",
                    style={"color": MUTED, "fontSize": "12px",
                           "margin": "0 0 12px 0", "lineHeight": "1.6"}),
                html.Div([
                    dcc.Input(
                        id=f"{p}-fim-cale",
                        type="text",
                        placeholder=r"ex: C:\Windows\System32\drivers\etc\hosts",
                        style=inp({"flex": "1", "minWidth": "260px",
                                   "fontSize": "12px"})),
                    html.Button(
                        "📂 Browse",
                        id=f"{p}-fim-browse",
                        n_clicks=0,
                        style=btn("#1e40af", "#93c5fd")
                    ),
                    html.Button(
                        "+ Adauga la monitorizare",
                        id=f"{p}-fim-add",
                        n_clicks=0,
                        style=btn("#166534", "white")),
                ], style={
                    "display": "flex", "gap": "10px", "flexWrap": "wrap",
                    "alignItems": "center", "marginBottom": "8px",
                }),
                html.Div(id=f"{p}-fim-msg",
                         style={"fontSize": "12px", "color": "#86efac",
                                "marginBottom": "8px"}),
                html.Div(id=f"{p}-fim-lista"),
            ]),

            dcc.Store(id=f"{p}-edit-id",      data=None),
            dcc.Store(id=f"{p}-save-store",   data=0),
            dcc.Store(id=f"{p}-ml-act-store", data=0),
            dcc.Store(id=f"{p}-fim-store",    data=0),
            dcc.Interval(id=f"{p}-interval",  interval=6000, n_intervals=0),
            dcc.Interval(id=f"{p}-ml-interval", interval=2000, n_intervals=0),
        ])


    def register_callbacks(self, app):
        p = self.P


        @app.callback(
            Output(f"{p}-detectori-lista", "children"),
            Input(f"{p}-interval",       "n_intervals"),
            Input(f"{p}-det-save-store", "data"),
        )
        def refresh_detectori(_, _save):
            params_db = self.state.db.get_config_detectori()
            if not params_db:
                return html.P("Nicio configuratie disponibila.",
                              style={"color": MUTED})

            valori = {(r["detector"], r["param"]): r["valoare"]
                      for r in params_db}
            elemente = []
            for detector, meta in DETECTORI_META.items():
                randuri = []
                for param, eticheta in meta["params"].items():
                    val = valori.get((detector, param), "—")
                    randuri.append(
                        html.Div([
                            html.Span(eticheta + ":",
                                      style={"color": MUTED, "fontSize": "12px",
                                             "flex": "1",
                                             "paddingRight": "12px"}),
                            dcc.Input(
                                id={"type": f"{p}-det-val",
                                    "index": f"{detector}||{param}"},
                                type="number", value=val, step=0.1,
                                style=inp({"width": "90px",
                                           "marginRight": "8px",
                                           "fontSize": "12px",
                                           "padding": "4px 8px"})),
                            html.Button(
                                "Salveaza",
                                id={"type": f"{p}-det-save",
                                    "index": f"{detector}||{param}"},
                                n_clicks=0,
                                style=btn("#1e40af", "#93c5fd",
                                          {"fontSize": "11px",
                                           "padding": "3px 10px"})),
                        ], style={"display": "flex", "alignItems": "center",
                                  "padding": "5px 0",
                                  "borderBottom": f"1px solid {BORDER}30"}))

                elemente.append(html.Div([
                    html.Div([
                        html.Span(detector,
                                  style={"color": ACCENT,
                                         "fontWeight": "700",
                                         "fontSize": "14px"}),
                    ], style={"marginBottom": "6px"}),
                    html.P(meta["descriere"],
                           style={"color": MUTED, "fontSize": "12px",
                                  "margin": "0 0 10px 0",
                                  "lineHeight": "1.6",
                                  "borderLeft": f"3px solid {ACCENT}55",
                                  "paddingLeft": "10px"}),
                    html.Div(randuri),
                ], style={"backgroundColor": f"{ACCENT}08",
                          "border": f"1px solid {ACCENT}22",
                          "borderRadius": "8px",
                          "padding": "14px 16px",
                          "marginBottom": "12px"}))

            return elemente

        @app.callback(
            Output(f"{p}-det-save-store", "data"),
            Input({"type": f"{p}-det-save",
                   "index": dash.dependencies.ALL}, "n_clicks"),
            State({"type": f"{p}-det-val",
                   "index": dash.dependencies.ALL}, "value"),
            State({"type": f"{p}-det-val",
                   "index": dash.dependencies.ALL}, "id"),
            State(f"{p}-det-save-store", "data"),
            prevent_initial_call=True,
        )
        def salveaza_detector(saves, values, ids, counter):
            ctx = dash.callback_context
            if not ctx.triggered or not any(c for c in saves if c):
                raise PreventUpdate
            try:
                prop = ctx.triggered[0]["prop_id"]
                info = json.loads(prop.split(".")[0])
                key  = info["index"]
                for i, id_obj in enumerate(ids):
                    if id_obj["index"] == key:
                        val = values[i]; break
                else:
                    raise PreventUpdate
                detector, param = key.split("||", 1)
                self.state.db.update_config_detector(detector, param, float(val))
            except Exception as e:
                print(f"[SETARI] Eroare salvare config: {e}")
            return (counter or 0) + 1

        @app.callback(
            Output(f"{p}-ml-extern-row", "style"),
            Input(f"{p}-ml-sursa", "value"),
        )
        def toggle_extern(sursa):
            return {"display": "block"} if sursa == "extern" \
                   else {"display": "none"}


        @app.callback(
            Output(f"{p}-ml-extern-store", "data"),
            Output(f"{p}-ml-extern-cale",  "children"),
            Input(f"{p}-ml-browse", "n_clicks"),
            prevent_initial_call=True,
        )
        def browse_extern(_):
            try:
                import tkinter as tk
                from tkinter import filedialog
                root = tk.Tk(); root.withdraw()
                root.wm_attributes("-topmost", True)
                cale = filedialog.askopenfilename(
                    title="Selecteaza DB pentru antrenare ML",
                    filetypes=[("SQLite Database", "*.db"),
                               ("Toate fisierele", "*.*")])
                root.destroy()
                if cale:
                    return cale, cale
                return None, "Niciun fisier selectat"
            except Exception as e:
                return None, f"Eroare: {e}"


        @app.callback(
            Output(f"{p}-ml-btns",         "children"),
            Output(f"{p}-ml-status-badge", "children"),
            Output(f"{p}-ml-status-badge", "style"),
            Input(f"{p}-ml-interval",   "n_intervals"),
            Input(f"{p}-ml-act-store",  "data"),
        )
        def refresh_ml_ui(_, _act):
            status           = self.state.ml_status
            date_ok, date_msg = self.state.are_date_suficiente_ml()

            STATUS_MAP = {
                "ready":    ("● Niciun model",    "#475569", "#1e293b"),
                "training": ("⟳ Antrenare...",   "#fde68a", "#422006"),
                "trained":  ("✓ Model antrenat",  "#86efac", "#052e16"),
            }
            txt, fg, bg = STATUS_MAP.get(status, STATUS_MAP["ready"])
            badge_style = {
                "fontSize": "11px", "fontWeight": "700",
                "color": fg, "backgroundColor": bg,
                "padding": "2px 8px", "borderRadius": "4px",
                "border": f"1px solid {fg}44",
            }

            if status == "training":
                btn_porneste = _btn_ml(
                    "⟳ Antrenare in curs...", "#166534", "white",
                    enabled=False, btn_id=f"{p}-ml-btn-porneste")
                btn_opreste  = _btn_ml(
                    "■ Opreste antrenarea", "#7f1d1d", "#fca5a5",
                    enabled=True,  btn_id=f"{p}-ml-btn-opreste")
                btn_sterge   = _btn_ml(
                    "🗑 Sterge model", "#7f1d1d", "#fca5a5",
                    enabled=False, btn_id=f"{p}-ml-btn-sterge")

            elif status == "trained":
                btn_porneste = _btn_ml(
                    "↻ Reantreneaza", "#166534", "white",
                    enabled=date_ok, btn_id=f"{p}-ml-btn-porneste")
                btn_opreste  = _btn_ml(
                    "■ Opreste antrenarea", "#7f1d1d", "#fca5a5",
                    enabled=False, btn_id=f"{p}-ml-btn-opreste")
                btn_sterge   = _btn_ml(
                    "🗑 Sterge model", "#7f1d1d", "#fca5a5",
                    enabled=True,  btn_id=f"{p}-ml-btn-sterge")

            else: 
                btn_porneste = _btn_ml(
                    "▶ Porneste antrenarea", "#166534", "white",
                    enabled=date_ok, btn_id=f"{p}-ml-btn-porneste")
                btn_opreste  = _btn_ml(
                    "■ Opreste antrenarea", "#7f1d1d", "#fca5a5",
                    enabled=False, btn_id=f"{p}-ml-btn-opreste")
                btn_sterge   = _btn_ml(
                    "🗑 Sterge model", "#7f1d1d", "#fca5a5",
                    enabled=False, btn_id=f"{p}-ml-btn-sterge")

            culoare_msg = "#86efac" if date_ok else "#fde68a"
            info_date   = html.Span(
                date_msg,
                style={"fontSize": "11px", "color": culoare_msg,
                       "marginLeft": "8px", "fontStyle": "italic"})

            return [btn_porneste, btn_opreste, btn_sterge, info_date], txt, badge_style


        @app.callback(
            Output(f"{p}-ml-act-store", "data"),
            Output(f"{p}-ml-msg",       "children"),
            Input(f"{p}-ml-btn-porneste", "n_clicks"),
            Input(f"{p}-ml-btn-opreste",  "n_clicks"),
            Input(f"{p}-ml-btn-sterge",   "n_clicks"),
            State(f"{p}-ml-sursa",        "value"),
            State(f"{p}-ml-ore",          "value"),
            State(f"{p}-ml-extern-store", "data"),
            State(f"{p}-ml-act-store",    "data"),
            prevent_initial_call=True,
        )
        def actiune_ml(c_porneste, c_opreste, c_sterge,
                       sursa, ore, cale_extern, counter):
            ctx = dash.callback_context
            if not ctx.triggered:
                raise PreventUpdate
            tid = ctx.triggered[0]["prop_id"]

            if "porneste" in tid and c_porneste:
                if self.state.ml_status == "training":
                    return counter, "Antrenare deja in curs."
                cale = cale_extern if sursa == "extern" else None
                ok   = self.state.incepe_antrenare(
                    ore=float(ore or 24), cale_db_extern=cale)
                msg  = (f"⟳ Antrenare pornita pe {ore}h de date istorice..."
                        if ok else "Nu se poate porni antrenarea acum.")

            elif "opreste" in tid and c_opreste:
                self.state.opreste_antrenare()
                msg = self.state.ml_msg

            elif "sterge" in tid and c_sterge:
                self.state.sterge_model()
                msg = self.state.ml_msg

            else:
                raise PreventUpdate

            return (counter or 0) + 1, msg

        @app.callback(
            Output(f"{p}-ml-msg", "children", allow_duplicate=True),
            Input(f"{p}-ml-interval", "n_intervals"),
            prevent_initial_call=True,
        )
        def sync_ml_msg(_):
            return self.state.ml_msg


        @app.callback(
            Output(f"{p}-det-toggle-area", "children"),
            Input(f"{p}-ml-interval",  "n_intervals"),
            Input(f"{p}-ml-act-store", "data"),
        )
        def refresh_toggle(_, _act):
            activ      = self.state.detectie_ml_activa
            are_model  = (self.state.ml_status == "trained")

            if activ:
                culoare_txt = "#86efac"
                bg_stare    = "#052e16"
                txt_stare   = "● ACTIVA"
                btn_label   = "Dezactiveaza detectia"
                btn_bg, btn_fg = "#7f1d1d", "#fca5a5"
                btn_enabled = True
            elif are_model:
                culoare_txt = "#f87171"
                bg_stare    = "#450a0a"
                txt_stare   = "○ INACTIVA"
                btn_label   = "Activeaza detectia"
                btn_bg, btn_fg = "#166534", "white"
                btn_enabled = True
            else:
                culoare_txt = "#475569"
                bg_stare    = "#1e293b"
                txt_stare   = "○ INACTIVA"
                btn_label   = "Activeaza detectia"
                btn_bg, btn_fg = "#1e293b", "#475569"
                btn_enabled = False

            if btn_enabled:
                btn_style = {
                    "background": btn_bg, "color": btn_fg,
                    "border": "none", "borderRadius": "6px",
                    "padding": "6px 14px", "cursor": "pointer",
                    "fontSize": "12px", "fontWeight": "600",
                }
            else:
                btn_style = {
                    "background": "#1e293b", "color": "#475569",
                    "border": "1px solid #334155", "borderRadius": "6px",
                    "padding": "6px 14px", "cursor": "not-allowed",
                    "fontSize": "12px", "fontWeight": "600",
                    "opacity": "0.55",
                }

            return [
                html.Span(txt_stare, style={
                    "fontSize": "12px", "fontWeight": "700",
                    "color": culoare_txt, "backgroundColor": bg_stare,
                    "padding": "4px 10px", "borderRadius": "4px",
                    "border": f"1px solid {culoare_txt}44",
                    "fontFamily": "monospace",
                }),
                html.Button(
                    btn_label,
                    id=f"{p}-ml-btn-toggle",
                    n_clicks=0,
                    disabled=not btn_enabled,
                    style=btn_style),
                html.Span(
                    "Antreneaza mai intai un model." if not are_model else "",
                    style={"fontSize": "11px", "color": "#475569",
                           "marginLeft": "8px"}),
            ]

        @app.callback(
            Output(f"{p}-ml-act-store", "data", allow_duplicate=True),
            Input(f"{p}-ml-btn-toggle", "n_clicks"),
            State(f"{p}-ml-act-store", "data"),
            prevent_initial_call=True,
        )
        def toggle_detectie(n, counter):
            if not n:
                raise PreventUpdate
            self.state.toggle_detectie_ml()
            return (counter or 0) + 1


        @app.callback(
            Output(f"{p}-r-add-status", "children"),
            Input(f"{p}-r-add", "n_clicks"),
            State(f"{p}-r-nume",      "value"),
            State(f"{p}-r-protocol",  "value"),
            State(f"{p}-r-port",      "value"),
            State(f"{p}-r-flags",     "value"),
            State(f"{p}-r-prag",      "value"),
            State(f"{p}-r-fereastra", "value"),
            State(f"{p}-r-sev",       "value"),
            prevent_initial_call=True,
        )
        def adauga(_, nume, proto, port, flags, prag, fereastra, sev):
            ok_name, err_name = validate_rule_name(nume)
            ok_port, err_port = validate_port(port, allow_empty=True)
            ok_flags, err_flags = validate_tcp_flags(flags, allow_empty=True)
            if not prag:
                return "Completeaza cel putin Numele si Pragul."
            if not ok_name:
                return err_name
            if not ok_port:
                return err_port
            if not ok_flags:
                return err_flags
            try:
                self.state.db.inserare_regula(
                    nume=nume, protocol=proto,
                    port_destinatie=port,
                    tcp_flags_contine=flags,
                    prag_count=int(prag),
                    fereastra_secunde=int(fereastra or 60),
                    severitate=sev)
                return f"✓ Regula '{nume}' adaugata."
            except Exception as e:
                return f"Eroare: {e}"

        @app.callback(
            Output(f"{p}-r-add", "disabled"),
            Output(f"{p}-r-add-help", "children"),
            Input(f"{p}-r-nume", "value"),
            Input(f"{p}-r-port", "value"),
            Input(f"{p}-r-flags", "value"),
            Input(f"{p}-r-prag", "value"),
        )
        def valideaza_form_add(nume, port, flags, prag):
            ok_name, err_name = validate_rule_name(nume)
            ok_port, err_port = validate_port(port, allow_empty=True)
            ok_flags, err_flags = validate_tcp_flags(flags, allow_empty=True)
            if not prag:
                return True, "Pragul este obligatoriu."
            for ok, err in [(ok_name, err_name), (ok_port, err_port), (ok_flags, err_flags)]:
                if not ok:
                    return True, err
            return False, "Format valid. Poti adauga regula."

        @app.callback(
            Output(f"{p}-edit-id", "data"),
            Input({"type": f"{p}-btn-edit",
                   "index": dash.dependencies.ALL}, "n_clicks"),
            State(f"{p}-edit-id", "data"),
            prevent_initial_call=True,
        )
        def toggle_edit(clicks, current):
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
            Output(f"{p}-save-store", "data"),
            Output(f"{p}-edit-id",   "data", allow_duplicate=True),
            Input({"type": f"{p}-btn-save",
                   "index": dash.dependencies.ALL}, "n_clicks"),
            State({"type": f"{p}-edit-proto",
                   "index": dash.dependencies.ALL}, "value"),
            State({"type": f"{p}-edit-port",
                   "index": dash.dependencies.ALL}, "value"),
            State({"type": f"{p}-edit-flags",
                   "index": dash.dependencies.ALL}, "value"),
            State({"type": f"{p}-edit-prag",
                   "index": dash.dependencies.ALL}, "value"),
            State({"type": f"{p}-edit-fereastra",
                   "index": dash.dependencies.ALL}, "value"),
            State({"type": f"{p}-edit-sev",
                   "index": dash.dependencies.ALL}, "value"),
            State({"type": f"{p}-edit-activa",
                   "index": dash.dependencies.ALL}, "value"),
            State(f"{p}-save-store", "data"),
            prevent_initial_call=True,
        )
        def salveaza_regula(saves, protos, ports, flags, praguri,
                            ferestre, sevs, active, counter):
            ctx = dash.callback_context
            if not ctx.triggered or not any(c for c in saves if c):
                raise PreventUpdate
            try:
                info    = json.loads(ctx.triggered[0]["prop_id"].split(".")[0])
                idx     = info["index"]
                all_ids = [s["id"]["index"] for s in ctx.inputs_list[0]]
                pos     = next((i for i, v in enumerate(all_ids)
                                if v == idx), 0)
                if pos < len(ports):
                    ok_port, err_port = validate_port(ports[pos], allow_empty=True)
                    if not ok_port:
                        print(f"[SETARI] Port invalid la salvare: {err_port}")
                        return counter or 0, None
                if pos < len(flags):
                    ok_flags, err_flags = validate_tcp_flags(
                        flags[pos], allow_empty=True
                    )
                    if not ok_flags:
                        print(f"[SETARI] Flags invalide la salvare: {err_flags}")
                        return counter or 0, None
                self.state.db.update_regula(
                    idx,
                    protocol          = protos[pos]   if pos < len(protos)   else None,
                    port_destinatie   = ports[pos]    if pos < len(ports)    else None,
                    tcp_flags_contine = flags[pos]    if pos < len(flags)    else None,
                    prag_count        = praguri[pos]  if pos < len(praguri)  else None,
                    fereastra_secunde = ferestre[pos] if pos < len(ferestre) else None,
                    severitate        = sevs[pos]     if pos < len(sevs)     else None,
                    activa = 1 if (active[pos] if pos < len(active)
                                   else ["on"]) else 0,
                )
            except Exception as e:
                print(f"[SETARI] Eroare salvare regula: {e}")
            return (counter or 0) + 1, None

        @app.callback(
            Output(f"{p}-save-store", "data", allow_duplicate=True),
            Input({"type": f"{p}-btn-del",
                   "index": dash.dependencies.ALL}, "n_clicks"),
            State(f"{p}-save-store", "data"),
            prevent_initial_call=True,
        )
        def sterge(clicks, counter):
            ctx = dash.callback_context
            if not ctx.triggered or not any(c for c in clicks if c):
                raise PreventUpdate
            try:
                info = json.loads(ctx.triggered[0]["prop_id"].split(".")[0])
                self.state.db.sterge_regula(info["index"])
            except Exception:
                pass
            return (counter or 0) + 1

        @app.callback(
            Output(f"{p}-r-lista", "children"),
            Input(f"{p}-interval",     "n_intervals"),
            Input(f"{p}-r-add-status", "children"),
            Input(f"{p}-save-store",   "data"),
            Input(f"{p}-edit-id",      "data"),
        )
        def refresh_reguli(_, _add, _save, edit_id):
            reguli = self.state.db.get_toate_regulile()
            if not reguli:
                return [html.P("Nicio regula configurata.",
                               style={"color": MUTED, "padding": "20px"})]

            elemente = []
            for r in reguli:
                este_editata = (edit_id == r["id"])
                culoare_on   = "#86efac" if r["activa"] else "#f87171"

                if este_editata:
                    rand = html.Div([
                        html.Div([
                            html.Span(r["nume"],
                                      style={"fontWeight": "700",
                                             "color": TEXT,
                                             "fontSize": "13px",
                                             "marginRight": "10px"}),
                            html.Span("(editare activa)",
                                      style={"color": ACCENT,
                                             "fontSize": "11px"}),
                        ], style={"marginBottom": "10px"}),
                        html.Div([
                            html.Div([html.Label("Protocol:", style=lbl()),
                                      dcc.Dropdown(
                                          id={"type": f"{p}-edit-proto",
                                              "index": r["id"]},
                                          options=[{"label": x, "value": x}
                                                   for x in ["all","TCP",
                                                             "UDP","OTHER"]],
                                          value=r["protocol"],
                                          style={**self.DD_STYLE,
                                                 "width": "100px"})]),
                            html.Div([html.Label("Port:", style=lbl()),
                                      dcc.Input(
                                          id={"type": f"{p}-edit-port",
                                              "index": r["id"]},
                                          type="text",
                                          value=r["port_destinatie"] or "",
                                          style=inp({"width": "90px"}))]),
                            html.Div([html.Label("Flags:", style=lbl()),
                                      dcc.Input(
                                          id={"type": f"{p}-edit-flags",
                                              "index": r["id"]},
                                          type="text",
                                          value=r["tcp_flags_contine"] or "",
                                          style=inp({"width": "85px"}))]),
                            html.Div([html.Label("Prag:", style=lbl()),
                                      dcc.Input(
                                          id={"type": f"{p}-edit-prag",
                                              "index": r["id"]},
                                          type="number",
                                          value=r["prag_count"],
                                          style=inp({"width": "80px"}))]),
                            html.Div([html.Label("Fereastra (s):", style=lbl()),
                                      dcc.Input(
                                          id={"type": f"{p}-edit-fereastra",
                                              "index": r["id"]},
                                          type="number",
                                          value=r["fereastra_secunde"],
                                          style=inp({"width": "90px"}))]),
                            html.Div([html.Label("Severitate:", style=lbl()),
                                      dcc.Dropdown(
                                          id={"type": f"{p}-edit-sev",
                                              "index": r["id"]},
                                          options=[{"label": x, "value": x}
                                                   for x in ["SCAZUTA","MEDIE",
                                                             "RIDICATA","CRITICA"]],
                                          value=r["severitate"],
                                          style={**self.DD_STYLE,
                                                 "width": "120px"})]),
                            html.Div([html.Label("Activa:", style=lbl()),
                                      dcc.Checklist(
                                          id={"type": f"{p}-edit-activa",
                                              "index": r["id"]},
                                          options=[{"label": "", "value": "on"}],
                                          value=["on"] if r["activa"] else [],
                                          style={"color": TEXT})]),
                            html.Button(
                                "💾 Salveaza",
                                id={"type": f"{p}-btn-save", "index": r["id"]},
                                n_clicks=0,
                                style=btn("#166534", "white",
                                          {"alignSelf": "flex-end"})),
                        ], style={"display": "flex", "gap": "8px",
                                  "flexWrap": "wrap",
                                  "alignItems": "flex-end"}),
                    ], style={"backgroundColor": f"{ACCENT}11",
                              "borderRadius": "8px", "padding": "14px",
                              "marginBottom": "8px",
                              "border": f"1px solid {ACCENT}44"})
                else:
                    rand = html.Div([
                        html.Div([
                            html.Span(
                                f"[{'ON' if r['activa'] else 'OFF'}] ",
                                style={"color": culoare_on,
                                       "fontWeight": "700",
                                       "fontSize": "12px",
                                       "fontFamily": "monospace"}),
                            html.Span(r["nume"],
                                      style={"color": TEXT,
                                             "fontWeight": "600",
                                             "fontSize": "13px",
                                             "marginRight": "10px"}),
                            html.Span(
                                f"{r['protocol']}  "
                                f"port:{r['port_destinatie'] or '*'}  "
                                f"flags:{r['tcp_flags_contine'] or '*'}  "
                                f"prag:{r['prag_count']}  "
                                f"fereastra:{r['fereastra_secunde']}s",
                                style={"color": MUTED, "fontSize": "12px",
                                       "fontFamily": "monospace"}),
                            badge_sev(r["severitate"]),
                        ], style={"flex": "1"}),
                        html.Div([
                            html.Button(
                                "✏ Editeaza",
                                id={"type": f"{p}-btn-edit",
                                    "index": r["id"]},
                                n_clicks=0,
                                style=btn("#1e3a5f", "#93c5fd",
                                          {"fontSize": "11px",
                                           "padding": "3px 9px",
                                           "marginRight": "5px"})),
                            html.Button(
                                "🗑 Sterge",
                                id={"type": f"{p}-btn-del",
                                    "index": r["id"]},
                                n_clicks=0,
                                style=btn("#4c1d1d", "#fca5a5",
                                          {"fontSize": "11px",
                                           "padding": "3px 9px"})),
                        ]),
                    ], style={"display": "flex",
                              "justifyContent": "space-between",
                              "alignItems": "center",
                              "padding": "8px 12px",
                              "marginBottom": "5px",
                              "borderRadius": "6px",
                              "border": f"1px solid {BORDER}"})

                elemente.append(rand)
            return elemente

        @app.callback(
            Output(f"{p}-fim-cale", "value"),
            Input(f"{p}-fim-browse", "n_clicks"),
            prevent_initial_call=True,
        )
        def browse_fim_file(_):
            try:
                import tkinter as tk
                from tkinter import filedialog
                import os
                import dash
                
                root = tk.Tk()
                root.withdraw()
                root.wm_attributes("-topmost", True)
                
                cale = filedialog.askopenfilename(
                    title="Selecteaza fisier pentru FIM",
                    filetypes=[("Toate fisierele", "*.*")]
                )
                
                root.destroy()
                
                if cale:
                    return os.path.normpath(cale)
                
                return dash.no_update
                
            except Exception as e:
                print(f"[SETARI] Eroare la deschiderea dialogului FIM: {e}")
                return dash.no_update
            
        @app.callback(
            Output(f"{p}-fim-msg", "children"),
            Output(f"{p}-fim-store", "data"),
            Input(f"{p}-fim-add", "n_clicks"),
            Input({"type": f"{p}-fim-del", "index": dash.dependencies.ALL}, "n_clicks"),
            State(f"{p}-fim-cale", "value"),
            State(f"{p}-fim-store", "data"),
            prevent_initial_call=True,
        )
        def gestionare_fim(c_add, c_dels, cale, ctr):
            ctx = dash.callback_context
            if not ctx.triggered:
                raise PreventUpdate
                
            trigger_id = ctx.triggered[0]["prop_id"]
            msg = ""
            nou_ctr = (ctr or 0)

            if f"{p}-fim-add" in trigger_id:
                if not cale or not str(cale).strip():
                    return "Introduceti o cale completa catre fisier.", nou_ctr
                cale_n = os.path.normpath(str(cale).strip())
                ok = self.state.db_live.inserare_fim_cale_user(cale_n)
                if not ok:
                    return "Cale deja in lista sau nu s-a putut salva (baza read-only).", nou_ctr
                
                fm = getattr(self.state, "fim_monitor", None)
                if fm:
                    fm.adauga_fisier(cale_n)
                msg = f"✓ Adaugat la monitorizare: {cale_n}"
                nou_ctr += 1

            else:
                try:
                    info = json.loads(trigger_id.split(".")[0])
                    rid = int(info["index"])
                except Exception:
                    raise PreventUpdate
                    
                cale_rm = None
                for r in self.state.db_live.get_fim_cai_user():
                    if r["id"] == rid:
                        cale_rm = r["cale"]
                        break
                        
                if cale_rm:
                    self.state.db_live.sterge_fim_cale_user(rid)
                    fm = getattr(self.state, "fim_monitor", None)
                    if fm:
                        fm.scoate_fisier(cale_rm)
                    msg = f"🗑 Scos de la monitorizare: {os.path.basename(cale_rm)}"
                    nou_ctr += 1
                else:
                    raise PreventUpdate

            return msg, nou_ctr

        @app.callback(
            Output(f"{p}-fim-lista", "children"),
            Input(f"{p}-interval", "n_intervals"),
            Input(f"{p}-fim-store", "data"),
        )
        def fim_refresh(_, __):
            rows = self.state.db_live.get_fim_cai_user()
            if not rows:
                return html.P(
                    "Nicio cale suplimentara. Fisierele implicite "
                    "(hosts, services, …) raman activate din cod.",
                    style={"color": MUTED, "padding": "8px 0",
                           "fontSize": "12px"})

            elemente = []
            for r in rows:
                elemente.append(html.Div([
                    html.Span(r["cale"], style={
                        "fontFamily": "ui-monospace, monospace",
                        "fontSize": "12px",
                        "color": TEXT,
                        "flex": "1",
                        "wordBreak": "break-all",
                    }),
                    html.Button(
                        "sterge",
                        id={"type": f"{p}-fim-del", "index": r["id"]},
                        n_clicks=0,
                        style=btn("#4c1d1d", "#fca5a5",
                                    {"fontSize": "11px",
                                     "padding": "3px 10px"})),
                ], style={
                    "display": "flex",
                    "justifyContent": "space-between",
                    "alignItems": "center",
                    "gap": "10px",
                    "padding": "8px 10px",
                    "marginBottom": "6px",
                    "borderRadius": "6px",
                    "border": f"1px solid {BORDER}",
                }))
            return elemente