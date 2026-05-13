"""
dashboard.py - Orchestratorul principal HIDS.
Layout: sidebar fix la stanga + continut la dreapta.
Sidebar contine: titlu, toggle Live/Pasiv, meniu sectiuni, statusuri ML.
"""
import json
import time
import dash
from dash import dcc, html
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate

from dashboard_utils import (
    get_ip_gazda, DARK, CARD, TEXT, MUTED, BORDER, ACCENT, DARK2,
)
from dashboard_trafic      import SecțiuneTrafic
from dashboard_statistici  import SecțiuneStatistici
from dashboard_alerte      import SecțiuneAlerte
from dashboard_comunicatii import SecțiuneComunicatii
from dashboard_setari      import SecțiuneSetari
from dashboard_pasiv       import SecțiunePasiva


# ─── Constante sidebar ────────────────────────────────────────────────────────
SIDEBAR_W   = "236px"
SIDEBAR_BG  = "#0c1222"
FONT_UI = "'DM Sans', 'Inter', system-ui, sans-serif"

SECTIUNI_LIVE = [
    ("trafic",      "📡  Trafic"),
    ("statistici",  "📊  Statistici"),
    ("alerte",      "🔔  Alerte"),
    ("comunicatii", "↔   Comunicatii"),
    ("setari",      "⚙   Setari"),
]


def _nav_item(label: str, value: str, activ: bool) -> html.Div:
    if activ:
        stil = {
            "background": ("linear-gradient(90deg, rgba(59,130,246,0.22) 0%, "
                           "rgba(59,130,246,0.06) 100%)"),
            "color": TEXT,
            "borderLeft": f"3px solid {ACCENT}",
            "fontWeight": "600",
        }
    else:
        stil = {
            "background": "transparent",
            "color": MUTED,
            "borderLeft": "3px solid transparent",
            "fontWeight": "500",
        }
    stil.update({
        "padding": "10px 14px 10px 12px",
        "fontSize": "13px",
        "letterSpacing": "0.02em",
        "borderRadius": "0 8px 8px 0",
        "marginBottom": "4px",
        "cursor": "pointer",
        "userSelect": "none",
        "transition": "background .15s, color .15s",
        "whiteSpace": "nowrap",
    })
    return html.Div(label,
                    id={"type": "nav-item", "index": value},
                    n_clicks=0,
                    style=stil)


def _mode_btn(label: str, value: str, activ: bool) -> html.Div:
    if activ:
        stil = {
            "background": ACCENT,
            "color": "white",
            "fontWeight": "600",
            "boxShadow": "0 1px 2px rgba(0,0,0,0.25)",
        }
    else:
        stil = {"background": "transparent", "color": MUTED, "fontWeight": "500"}
    stil.update({
        "fontSize": "11px",
        "letterSpacing": "0.06em",
        "padding": "8px 0",
        "flex": "1",
        "textAlign": "center",
        "cursor": "pointer",
        "borderRadius": "6px",
        "userSelect": "none",
    })
    return html.Div(label,
                    id={"type": "mode-btn", "index": value},
                    n_clicks=0,
                    style=stil)


class DashboardRetea:

    def __init__(self, app_state):
        self.state    = app_state
        self.app = dash.Dash(
            __name__,
            title="HIDS Monitor",
            suppress_callback_exceptions=True,
            external_stylesheets=[
                "https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@"
                "9..40,400..700&display=swap",
            ],
            meta_tags=[
                {"name": "viewport", "content":
                 "width=device-width, initial-scale=1"},
                {"name": "theme-color", "content": "#0f172a"},
            ],
        )
        self.ip_gazda = get_ip_gazda()
        print(f"[DASHBOARD] IP gazda detectat: {self.ip_gazda}")

        self._trafic     = SecțiuneTrafic(app_state,     self.ip_gazda, "lt")
        self._statistici = SecțiuneStatistici(app_state, self.ip_gazda, "lst")
        self._alerte     = SecțiuneAlerte(app_state,     "la")
        self._comun      = SecțiuneComunicatii(app_state, self.ip_gazda, "lc")
        self._setari     = SecțiuneSetari(app_state,     "ls")
        self._pasiv      = SecțiunePasiva(app_state)

        self._build_layout()
        self._register_callbacks()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _sidebar(self):
        return html.Div([

            html.Div([
                html.Div("HIDS", style={
                    "fontSize": "24px", "fontWeight": "800",
                    "color": TEXT, "lineHeight": "1", "letterSpacing": "-0.03em"}),
                html.Div("Monitor rețea & intruziuni",
                         style={"fontSize": "11px", "color": MUTED,
                                "marginTop": "5px", "fontWeight": "500"}),
            ], style={
                "padding": "22px 18px 18px 18px",
                "borderBottom": f"1px solid {BORDER}",
                "background": ("linear-gradient(180deg, "
                               "rgba(59,130,246,0.1) 0%, transparent 100%)"),
            }),

            html.Div(id="g-interfete",
                     style={"padding": "14px 14px 14px 14px",
                            "borderBottom": f"1px solid {BORDER}"}),

            html.Div([
                html.P("Sursă date", style={
                    "fontSize": "10px", "color": MUTED, "margin": "0 0 8px 2px",
                    "fontWeight": "700", "textTransform": "uppercase",
                    "letterSpacing": "0.1em"}),
                html.Div(id="mode-container",
                         style={"display": "flex",
                                "backgroundColor": DARK2,
                                "borderRadius": "8px", "padding": "4px",
                                "border": f"1px solid {BORDER}"}),
            ], style={"padding": "14px 14px 16px 14px",
                      "borderBottom": f"1px solid {BORDER}"}),

            html.Div([
                html.P("Navigare", style={
                    "fontSize": "10px", "color": MUTED,
                    "margin": "12px 0 8px 14px",
                    "fontWeight": "700", "textTransform": "uppercase",
                    "letterSpacing": "0.1em"}),
                html.Div(
                    id="nav-container",
                    style={
                        "flex": "1",
                        "minHeight": "0",
                        "overflowY": "auto",
                        "paddingBottom": "8px",
                    },
                ),
            ], style={"display": "flex", "flexDirection": "column", "flex": "1"}),

            html.Div([
                html.P("Machine learning", style={
                    "fontSize": "10px", "color": MUTED, "margin": "0 0 10px 0",
                    "fontWeight": "700", "textTransform": "uppercase",
                    "letterSpacing": "0.1em"}),
                html.Div([
                    html.Span("Antrenare",
                              style={"fontSize": "11px", "color": MUTED,
                                     "fontWeight": "500", "minWidth": "72px"}),
                    html.Span(id="g-badge-antrenare"),
                ], style={"display": "flex", "justifyContent": "space-between",
                          "alignItems": "center", "marginBottom": "8px", "gap": "8px"}),
                html.Div([
                    html.Span("Detecție",
                              style={"fontSize": "11px", "color": MUTED,
                                     "fontWeight": "500", "minWidth": "72px"}),
                    html.Span(id="g-badge-detectie"),
                ], style={"display": "flex", "justifyContent": "space-between",
                          "alignItems": "center", "gap": "8px"}),
            ], style={
                "padding": "16px 16px 20px 16px",
                "borderTop": f"1px solid {BORDER}",
                "marginTop": "auto",
                "background": f"linear-gradient(0deg, {DARK2} 40%, transparent 100%)",
            }),

        ], id="app-sidebar", className="sidebar-open", style={
            "width": SIDEBAR_W,
            "minWidth": SIDEBAR_W,
            "backgroundColor": SIDEBAR_BG,
            "minHeight": "100vh",
            "display": "flex",
            "flexDirection": "column",
            "borderRight": f"1px solid {BORDER}",
            "boxShadow": "4px 0 24px rgba(0,0,0,0.35)",
            "position": "fixed",
            "top": "0", "left": "0", "bottom": "0",
            "overflowY": "auto",
            "overflowX": "hidden",
            "zIndex": "100",
        })

    def _build_layout(self):
        self.app.layout = html.Div([
            html.Button("☰ Meniu", id="sidebar-toggle-btn", n_clicks=0,
                        style={"position": "fixed", "top": "10px", "left": "10px",
                               "zIndex": "200", "display": "none"}),
            self._sidebar(),

            # Zona continut — Live și Pasiv montate separat (Pasiv nu se pierde la comutare)
            html.Div([
                html.Div(
                    id="live-tab-content",
                    style={
                        "padding": "26px 32px 40px 32px",
                        "minHeight": "100vh",
                        "maxWidth": "1580px",
                        "margin": "0 auto",
                    }),
                html.Div(
                    id="pasiv-tab-content",
                    children=self._pasiv.layout(),
                    style={
                        "display": "none",
                        "padding": "26px 32px 40px 32px",
                        "minHeight": "100vh",
                        "maxWidth": "1580px",
                        "margin": "0 auto",
                    }),
            ], id="app-content", className="content-with-sidebar", style={
                "marginLeft": SIDEBAR_W,
                "flex": "1",
                "minWidth": "0",
                "background": (f"radial-gradient(ellipse 100% 70% at 100% -10%, "
                               f"rgba(59,130,246,0.08), transparent 55%), {DARK}"),
            }),

            dcc.Store(id="nav-sectiune",  data="trafic"),
            dcc.Store(id="nav-mod",       data="live"),
            dcc.Store(id="nav-mod-sync",  data="live"),
            dcc.Store(id="alerte-last-ts", data=0),
            dcc.Store(id="sidebar-open", data=True),
            dcc.Store(id="pa-scan-tick", data=0),
            dcc.Interval(id="g-interval", interval=2500, n_intervals=0),

        ], style={
            "fontFamily": FONT_UI,
            "backgroundColor": DARK,
            "minHeight": "100vh",
            "color": TEXT,
            "display": "flex",
            "-webkitFontSmoothing": "antialiased",
        })

    # ── Callbacks ─────────────────────────────────────────────────────────────

    def _register_callbacks(self):

        # Click nav item
        @self.app.callback(
            Output("nav-sectiune",  "data"),
            Output("alerte-last-ts", "data"),
            Input({"type": "nav-item", "index": dash.dependencies.ALL},
                  "n_clicks"),
            State("alerte-last-ts", "data"),
            prevent_initial_call=True,
        )
        def click_nav(clicks, last_ts):
            ctx = dash.callback_context
            if not ctx.triggered or not any(c for c in clicks if c):
                raise PreventUpdate
            info = json.loads(ctx.triggered[0]["prop_id"].split(".")[0])
            sectiune = info["index"]
            # Daca utilizatorul intra pe Alerte, reseteaza timestamp-ul
            nou_ts = time.time() if sectiune == "alerte" else last_ts
            return sectiune, nou_ts

        # Click mode btn
        @self.app.callback(
            Output("nav-mod", "data"),
            Input({"type": "mode-btn", "index": dash.dependencies.ALL},
                  "n_clicks"),
            prevent_initial_call=True,
        )
        def click_mode(clicks):
            ctx = dash.callback_context
            if not ctx.triggered or not any(c for c in clicks if c):
                raise PreventUpdate
            info = json.loads(ctx.triggered[0]["prop_id"].split(".")[0])
            return info["index"]

        @self.app.callback(
            Output("sidebar-open", "data"),
            Input("sidebar-toggle-btn", "n_clicks"),
            State("sidebar-open", "data"),
            prevent_initial_call=True,
        )
        def toggle_sidebar(_, is_open):
            return not bool(is_open)

        @self.app.callback(
            Output("app-sidebar", "className"),
            Output("app-content", "className"),
            Input("sidebar-open", "data"),
        )
        def sidebar_classes(is_open):
            if is_open:
                return "sidebar-open", "content-with-sidebar"
            return "sidebar-closed", "content-full"

        # Render meniu sidebar
        @self.app.callback(
            Output("nav-container",  "children"),
            Output("mode-container", "children"),
            Input("nav-sectiune",   "data"),
            Input("nav-mod",        "data"),
            Input("g-interval",     "n_intervals"),
            State("alerte-last-ts", "data"),
        )
        def render_nav(sectiune, mod, _, last_ts):
            # Numaram alertele noi de cand s-a vizitat ultima oara Alerte
            alerte_noi = 0
            if sectiune != "alerte":
                try:
                    alerte_noi = self.state.db.count_alerte(
                        ts_start=last_ts if last_ts else 0,
                        vazut=False)
                except Exception:
                    alerte_noi = 0

            mode_btns = [
                _mode_btn("⬤ Live",  "live",  mod == "live"),
                _mode_btn("⏱ Pasiv", "pasiv", mod == "pasiv"),
            ]
            if mod == "live":
                items = []
                for val, label in SECTIUNI_LIVE:
                    item = _nav_item(label, val, val == sectiune)
                    # Badge alerte noi
                    if val == "alerte" and alerte_noi > 0:
                        item = html.Div([
                            item,
                            html.Span(
                                str(alerte_noi) if alerte_noi < 100 else "99+",
                                style={
                                    "position": "absolute",
                                    "right": "10px",
                                    "top": "50%",
                                    "transform": "translateY(-50%)",
                                    "backgroundColor": "#ef4444",
                                    "color": "white",
                                    "fontSize": "10px",
                                    "fontWeight": "700",
                                    "minWidth": "18px",
                                    "height": "18px",
                                    "borderRadius": "9px",
                                    "display": "flex",
                                    "alignItems": "center",
                                    "justifyContent": "center",
                                    "padding": "0 4px",
                                    "fontFamily": "monospace",
                                }),
                        ], style={"position": "relative"})
                    items.append(item)
            else:
                items = [html.Div("Analiza Pasiva", style={
                    "padding": "12px 16px", "color": MUTED,
                    "fontSize": "12px", "fontStyle": "italic"})]
            return items, mode_btns

        # Continut Live (Pasiv ramane in pasiv-tab-content)
        @self.app.callback(
            Output("live-tab-content", "children"),
            Input("nav-sectiune", "data"),
            Input("nav-mod",      "data"),
        )
        def render_live(sectiune, mod):
            if mod != "live":
                raise PreventUpdate
            mapping = {
                "trafic":      self._trafic.layout,
                "statistici":  self._statistici.layout,
                "alerte":      self._alerte.layout,
                "comunicatii": self._comun.layout,
                "setari":      self._setari.layout,
            }
            return mapping.get(sectiune, lambda: [])()

        @self.app.callback(
            Output("live-tab-content", "style"),
            Output("pasiv-tab-content", "style"),
            Input("nav-mod", "data"),
        )
        def toggle_live_pasiv(mod):
            pad = {
                "padding": "26px 32px 40px 32px",
                "minHeight": "100vh",
                "maxWidth": "1580px",
                "margin": "0 auto",
            }
            if mod == "live":
                return {**pad}, {**pad, "display": "none"}
            return {**pad, "display": "none"}, pad

        @self.app.callback(
            Output("nav-mod-sync", "data"),
            Input("nav-mod", "data"),
        )
        def sync_mod_cu_state(mod):
            if mod == "live":
                self.state.activeaza_mod_live()
            else:
                self.state.enter_pasiv_mode()
            return mod or "live"

        # Interfete active
        @self.app.callback(
            Output("g-interfete", "children"),
            Input("g-interval", "n_intervals"),
        )
        def update_interfete(_):
            interfete = self.state.interfete_active
            if not interfete:
                return html.Div([
                    html.P("Interfețe captură", style={
                        "fontSize": "10px", "color": MUTED, "margin": "0 0 10px 0",
                        "fontWeight": "700", "textTransform": "uppercase",
                        "letterSpacing": "0.1em"}),
                    html.P("Detectare adaptoarelor…",
                           style={"fontSize": "12px", "color": MUTED, "margin": "0"}),
                ], style={
                    "padding": "12px",
                    "borderRadius": "10px",
                    "border": f"1px dashed {BORDER}",
                    "backgroundColor": "rgba(15,23,42,0.55)",
                })

            tip_meta = {
                "fizica":   ("Fizic", "#38bdf8"),
                "virtuala": ("Virtual", "#4ade80"),
                "manuala":  ("Manual", "#fcd34d"),
            }
            items = []
            for iface in interfete:
                tag, stripe = tip_meta.get(
                    iface.get("tip", "fizica"), ("Rețea", "#64748b"))
                nume    = iface.get("name") or "—"
                ip_addr = iface.get("ip") or "—"
                items.append(html.Div([
                    html.Div(style={
                        "width": "4px", "alignSelf": "stretch",
                        "backgroundColor": stripe, "flexShrink": "0",
                        "borderRadius": "2px",
                    }),
                    html.Div([
                        html.Div([
                            html.Span(nume, style={
                                "color": TEXT,
                                "fontSize": "12px",
                                "fontWeight": "600",
                                "overflow": "hidden",
                                "textOverflow": "ellipsis",
                                "whiteSpace": "nowrap",
                            }),
                            html.Span(tag.upper(), style={
                                "fontSize": "9px", "fontWeight": "700",
                                "color": stripe, "flexShrink": "0",
                                "letterSpacing": "0.06em",
                            }),
                        ], style={
                            "display": "flex", "justifyContent": "space-between",
                            "alignItems": "baseline", "gap": "6px", "marginBottom": "5px"}),
                        html.Div(ip_addr, style={
                            "fontSize": "11px", "color": MUTED,
                            "fontFamily": "ui-monospace, monospace"}),
                    ], style={
                        "flex": "1", "minWidth": "0",
                        "padding": "10px 12px 10px 0",
                    }),
                ], style={
                    "display": "flex", "gap": "0",
                    "marginBottom": "8px",
                    "borderRadius": "10px",
                    "overflow": "hidden",
                    "backgroundColor": CARD,
                    "border": f"1px solid {BORDER}",
                }))

            return html.Div([
                html.P("Interfețe captură",
                       style={
                           "fontSize": "10px", "color": MUTED,
                           "fontWeight": "700", "margin": "0 0 10px 4px",
                           "textTransform": "uppercase",
                           "letterSpacing": "0.1em"}),
                *items,
            ])

        # Statusuri ML
        @self.app.callback(
            Output("g-badge-antrenare", "children"),
            Output("g-badge-antrenare", "style"),
            Output("g-badge-detectie",  "children"),
            Output("g-badge-detectie",  "style"),
            Input("g-interval", "n_intervals"),
        )
        def update_ml_badges(_):
            ml = self.state.ml_status
            MAP = {
                "ready":    ("○ Niciun model", "#475569", "#1e293b"),
                "training": ("⟳ Antrenare...", "#fde68a", "#422006"),
                "trained":  ("✓ Activ",        "#86efac", "#052e16"),
            }
            a_txt, a_fg, a_bg = MAP.get(ml, MAP["ready"])
            badge_a = {"fontSize": "10px", "fontWeight": "600",
                       "color": a_fg, "backgroundColor": a_bg,
                       "padding": "4px 8px", "borderRadius": "6px",
                       "border": f"1px solid {a_fg}44",
                       "fontFamily": "ui-monospace, monospace"}

            activ   = self.state.detectie_ml_activa
            d_txt   = "Activ" if activ else "Oprit"
            d_fg    = "#86efac" if activ else "#f87171"
            d_bg    = "#052e16" if activ else "#450a0a"
            badge_d = {"fontSize": "10px", "fontWeight": "600",
                       "color": d_fg, "backgroundColor": d_bg,
                       "padding": "4px 8px", "borderRadius": "6px",
                       "border": f"1px solid {d_fg}44",
                       "fontFamily": "ui-monospace, monospace"}

            return a_txt, badge_a, d_txt, badge_d

        # Callbacks sectiuni
        for sectiune in [self._trafic, self._statistici, self._alerte,
                          self._comun, self._setari]:
            sectiune.register_callbacks(self.app)
        self._pasiv.register_callbacks(self.app)

    def start(self, host: str = "127.0.0.1", port: int = 8050,
              debug: bool = False):
        print(f"[DASHBOARD] http://{host}:{port}")
        self.app.run(host=host, port=port, debug=debug)