"""
dashboard_statistici.py - Sectiunea Statistici: KPI-uri alerte + grafice trafic.
"""
from datetime import datetime
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.graph_objects as go

from dashboard_utils import (
    card, sectiune_titlu, PLOTLY_LAYOUT,
    ACCENT, MUTED, TEXT, BORDER, CARD,
    PROTO_CULORI,
)


class SecțiuneStatistici:
    """
    Afiseaza:
    - KPI-uri: total alerte, in asteptare, nivel ridicat/critic, mediu, false positive
    - KPI pachete/secunda (1 min si 5 min)
    - Grafic pachete/secunda per IP sursa (exclus IP gazda)
    - Grafic distributie protocol in timp (stacked bar)
    """

    def __init__(self, app_state, ip_gazda: str, prefix: str = "lst"):
        self.state    = app_state
        self.ip_gazda = ip_gazda
        self.P        = prefix

    # ── Constructie KPI box ───────────────────────────────────────────────────

    @staticmethod
    def _kpi(valoare, eticheta: str, culoare: str = ACCENT):
        return html.Div([
            html.Div(str(valoare),
                     style={"fontSize": "28px", "fontWeight": "800",
                            "color": culoare, "lineHeight": "1"}),
            html.Div(eticheta,
                     style={"fontSize": "11px", "color": MUTED,
                            "marginTop": "4px", "textTransform": "uppercase",
                            "letterSpacing": "0.08em"}),
        ], style={"backgroundColor": CARD, "borderRadius": "10px",
                  "padding": "16px 20px",
                  "borderTop": f"3px solid {culoare}"})

    def layout(self):
        p = self.P
        return html.Div([
            # ── KPI alerte ────────────────────────────────────────────────────
            html.Div(id=f"{p}-kpi-alerte",
                     style={"display": "grid",
                            "gridTemplateColumns": "repeat(4, 1fr)",
                            "gap": "12px", "marginBottom": "12px"}),

            # ── KPI pachete/secunda ───────────────────────────────────────────
            html.Div(id=f"{p}-kpi-pps",
                     style={"display": "grid",
                            "gridTemplateColumns": "repeat(3, 1fr)",
                            "gap": "12px", "marginBottom": "12px"}),

            # ── Filtru Interfata pentru Grafice ───────────────────────────────
            html.Div([
                html.Label("Filtreaza graficele pe interfata:", style={"color": MUTED, "fontSize": "12px", "marginRight": "10px"}),
                dcc.Dropdown(id=f"{p}-graf-interfata",
                             options=[{"label": "Toate", "value": "all"}],
                             value="all", clearable=False,
                             style={"backgroundColor": CARD, "color": TEXT, "fontSize": "12px", "width": "200px"})
            ], style={"display": "flex", "alignItems": "center", "marginBottom": "12px"}),

            # ── Grafice ───────────────────────────────────────────────────────
            html.Div([
                card([
                    sectiune_titlu(
                        "Pachete/secundă per IP sursă (ultimele 5 minute)"),
                    dcc.Graph(id=f"{p}-graf-ip",
                              style={"height": "260px"},
                              config={"displayModeBar": False}),
                ], {"marginBottom": "0"}),
                card([
                    sectiune_titlu(
                        "Distributie protocol în timp (ultimele 5 minute)"),
                    dcc.Graph(id=f"{p}-graf-proto",
                              style={"height": "260px"},
                              config={"displayModeBar": False}),
                ], {"marginBottom": "0"}),
            ], style={"display": "grid",
                      "gridTemplateColumns": "1fr 1fr", "gap": "12px"}),

            dcc.Interval(id=f"{p}-interval", interval=5000, n_intervals=0),
        ])

    def _sursa_grafice(self, interfata_val):
        """DB combinat (toate interfetele) sau sesiunea per-interfata pentru grafice."""
        if not interfata_val or interfata_val == "all":
            return self.state.db
        return self.state.get_manager_interfata(interfata_val)

    def register_callbacks(self, app):
        p = self.P

        @app.callback(
            Output(f"{p}-graf-interfata", "options"),
            Output(f"{p}-kpi-alerte", "children"),
            Output(f"{p}-kpi-pps",    "children"),
            Output(f"{p}-graf-ip",    "figure"),
            Output(f"{p}-graf-proto", "figure"),
            Input(f"{p}-interval", "n_intervals"),
            Input(f"{p}-graf-interfata", "value"),
        )
        def actualizeaza(_, interfata_val):

            # Populam optiunile
            optiuni_iface = [{"label": "Toate", "value": "all"}]
            if self.state.interfete_active:
                for iface in self.state.interfete_active:
                    nume = iface.get("name", "")
                    if nume:
                        optiuni_iface.append({"label": nume, "value": nume})

            sursa = self._sursa_grafice(interfata_val)

            # ── KPI alerte ────────────────────────────────────────────────────
            st = self.state.db.get_statistici_alerte()
            nivel_ridicat = st.get("critica", 0) + st.get("ridicata", 0)
            kpi_alerte = [
                self._kpi(st.get("total", 0),
                          "Alerte Total", ACCENT),
                self._kpi(st.get("in_asteptare", 0),
                          "In Asteptare", "#fde68a"),
                self._kpi(nivel_ridicat,
                          "Ridicat / Critic", "#f87171"),
                self._kpi(st.get("medie", 0),
                          "Nivel Mediu", "#fb923c"),
            ]

            # ── KPI pachete/s ─────────────────────────────────────────────────
            pps_60  = self.state.db.get_avg_pachete_per_secunda(60)
            pps_300 = self.state.db.get_avg_pachete_per_secunda(300)
            kpi_pps = [
                self._kpi(f"{pps_60:.1f}",
                          "Pkt/s (ultimul minut)", "#7dd3fc"),
                self._kpi(f"{pps_300:.1f}",
                          "Pkt/s (ultimele 5 min)", "#7dd3fc"),
                self._kpi(st.get("false_positive", 0),
                          "False Positive confirmate", "#86efac"),
            ]

            # ── Grafic pachete/s per IP ───────────────────────────────────────
            rows_ip = []
            rows_pr = []
            if sursa is not None:
                rows_ip = sursa.get_pachete_per_secunda_per_ip(
                    interval_secunde=300, bucket_secunde=10,
                    ip_exclus=self.ip_gazda)
                rows_pr = sursa.get_distributie_protocol_timp(
                    interval_secunde=300, bucket_secunde=10)

            fig_ip = go.Figure()
            if rows_ip:
                totale = {}
                for r in rows_ip:
                    totale[r["src_ip"]] = totale.get(r["src_ip"], 0) + r["cnt"]
                top_ip = sorted(totale, key=totale.get, reverse=True)[:8]
                palette = ["#7dd3fc", "#86efac", "#fb923c", "#f87171",
                           "#d8b4fe", "#fde68a", "#f9a8d4", "#67e8f9"]
                for i, ip in enumerate(top_ip):
                    xs = [r["ts_bucket"] for r in rows_ip if r["src_ip"] == ip]
                    ys = [r["cnt"]       for r in rows_ip if r["src_ip"] == ip]
                    xf = [datetime.fromtimestamp(x).strftime("%H:%M:%S") for x in xs]
                    fig_ip.add_trace(go.Scatter(
                        x=xf, y=ys, name=ip, mode="lines",
                        line=dict(color=palette[i % len(palette)], width=2)))

            fig_ip.update_layout(**PLOTLY_LAYOUT, yaxis_title="pachete / 10s")

            # ── Grafic distributie protocol ───────────────────────────────────
            fig_pr = go.Figure()
            if rows_pr:
                protocoale = list({r["protocol"] for r in rows_pr})
                for proto in protocoale:
                    xs = [r["ts_bucket"] for r in rows_pr if r["protocol"] == proto]
                    ys = [r["cnt"]       for r in rows_pr if r["protocol"] == proto]
                    xf = [datetime.fromtimestamp(x).strftime("%H:%M:%S") for x in xs]
                    fig_pr.add_trace(go.Bar(
                        x=xf, y=ys, name=proto,
                        marker_color=PROTO_CULORI.get(proto, "#94a3b8")))
                fig_pr.update_layout(barmode="stack")

            fig_pr.update_layout(**PLOTLY_LAYOUT, yaxis_title="pachete / 10s")

            return optiuni_iface, kpi_alerte, kpi_pps, fig_ip, fig_pr