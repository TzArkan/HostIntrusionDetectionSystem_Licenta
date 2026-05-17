from dash import dcc, html
from dash.dependencies import Input, Output, State

from dashboard_utils import (
    btn, card, ACCENT, MUTED, CARD, DARK, BORDER,
    TAB_STYLE, TAB_SEL_STYLE,
)
from dashboard_trafic import SectiuneTrafic
from dashboard_alerte import SectiuneAlerte
from dashboard_utils import get_ip_gazda


class SectiunePasiva:

    def __init__(self, app_state):
        self.state  = app_state
        ip_g        = get_ip_gazda()
        self.trafic = SectiuneTrafic(app_state, ip_g, prefix="pt")
        self.alerte = SectiuneAlerte(app_state,       prefix="pa")

    def layout(self):
        return html.Div([
            card([
                html.H3("Selectie baza de date externa",
                        style={"color": "#e2e8f0", "fontSize": "15px",
                               "margin": "0 0 8px 0"}),
                html.P("Selecteaza un fisier .db SQLite exportat de pe alta masina. "
                       "Sistemul analizeaza traficul si alertele fara a modifica "
                       "datele live.",
                       style={"color": MUTED, "fontSize": "13px",
                              "margin": "0 0 14px 0"}),
                html.Div([
                    html.Div(id="p-cale-afisata",
                             children="Niciun fisier selectat",
                             style={"flex": "1", "color": MUTED,
                                    "fontSize": "13px", "fontFamily": "monospace",
                                    "padding": "7px 12px",
                                    "backgroundColor": DARK,
                                    "borderRadius": "6px",
                                    "border": f"1px solid {BORDER}",
                                    "marginRight": "10px"}),
                    html.Button("📂 Selecteaza fisier",
                                id="p-browse-btn",
                                style=btn("#1e40af", "#93c5fd")),
                    html.Button("▶ Incarca",
                                id="p-load-btn",
                                style={**btn("#166534", "white"),
                                       "marginLeft": "8px"}),
                ], style={"display": "flex", "alignItems": "center",
                          "marginBottom": "10px"}),
                html.Div(id="p-load-status",
                         style={"fontSize": "12px", "color": MUTED}),
                dcc.Store(id="p-cale-store"),
            ]),
            html.Div(id="p-continut",
                     children=[html.P(
                         "Incarca un fisier pentru a vedea datele.",
                         style={"color": MUTED, "textAlign": "center",
                                "padding": "60px"})]),
        ])

    def register_callbacks(self, app):
        @app.callback(
            Output("p-cale-store",   "data"),
            Output("p-cale-afisata", "children"),
            Input("p-browse-btn", "n_clicks"),
            prevent_initial_call=True,
        )
        def browse(_):
            try:
                import tkinter as tk
                from tkinter import filedialog
                root = tk.Tk()
                root.withdraw()
                root.wm_attributes("-topmost", True)
                cale = filedialog.askopenfilename(
                    title="Selecteaza baza de date SQLite HIDS",
                    filetypes=[("SQLite Database", "*.db"),
                               ("Toate fisierele", "*.*")])
                root.destroy()
                if cale:
                    return cale, cale
                return None, "Niciun fisier selectat"
            except Exception as e:
                return None, f"Eroare: {e}"

        @app.callback(
            Output("p-load-status", "children"),
            Output("p-continut",    "children"),
            Input("p-load-btn", "n_clicks"),
            State("p-cale-store", "data"),
            prevent_initial_call=True,
        )
        def incarca(_, cale):
            if not cale:
                return "Selecteaza mai intai un fisier.", []
            
            ok, mesaj = self.state.activeaza_mod_pasiv(cale)
            if not ok:
                from dash import html
                return html.Span(mesaj, style={"color": "#fca5a5"}), []

            continut = [
                dcc.Tabs(id="p-subtabs", value="p-trafic",
                    style={"marginBottom": "14px"},
                    children=[
                        dcc.Tab(label="Trafic", value="p-trafic",
                                style=TAB_STYLE, selected_style=TAB_SEL_STYLE),
                        dcc.Tab(label="Alerte", value="p-alerte",
                                style=TAB_STYLE, selected_style=TAB_SEL_STYLE),
                    ]),
                html.Div(id="p-subtab-content"),
            ]
            return mesaj, continut

        @app.callback(
            Output("p-subtab-content", "children"),
            Input("p-subtabs", "value"),
        )
        def render_subtab(tab):
            if tab == "p-trafic":
                return self.trafic.layout()
            if tab == "p-alerte":
                return self.alerte.layout()
            return []

        self.trafic.register_callbacks(app)
        self.alerte.register_callbacks(app)