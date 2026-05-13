"""
dashboard_utils.py - Constante de tema, helper-e UI si detectare IP gazda.
Importat de toate modulele dashboard_*.py.
"""
import socket
from dash import html, dcc
import plotly.graph_objects as go

# ─── CULORI / TEMA ────────────────────────────────────────────────────────────
DARK   = "#0f172a"
CARD   = "#1e293b"
TEXT   = "#e2e8f0"
MUTED  = "#94a3b8"
BORDER = "#334155"
ACCENT = "#3b82f6"
DARK2  = "#0d1424"

SEV_CULORI = {
    "SCAZUTA": "#86efac",
    "MEDIE":   "#fde68a",
    "RIDICATA":"#fb923c",
    "CRITICA": "#f87171",
}
PROTO_CULORI = {"TCP": "#7dd3fc", "UDP": "#86efac", "OTHER": "#d8b4fe"}

PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color=TEXT, size=11),
    margin=dict(l=50, r=20, t=30, b=40),
    legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color=MUTED)),
    xaxis=dict(gridcolor=BORDER, color=MUTED),
    yaxis=dict(gridcolor=BORDER, color=MUTED),
)

# ─── DETECTARE IP GAZDA ───────────────────────────────────────────────────────

def get_ip_gazda() -> str:
    """Detecteaza IP-ul masinii gazda prin conexiune UDP fictiva la 8.8.8.8."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

# ─── HELPER-E UI GENERALE ────────────────────────────────────────────────────

def inp(extra: dict = None) -> dict:
    """Stilul standard pentru dcc.Input."""
    s = {"backgroundColor": DARK, "color": TEXT,
         "border": f"1px solid {BORDER}", "borderRadius": "6px",
         "padding": "6px 10px", "fontSize": "13px"}
    if extra:
        s.update(extra)
    return s

def lbl() -> dict:
    """Stilul standard pentru Label."""
    return {"fontSize": "12px", "color": MUTED,
            "display": "block", "marginBottom": "3px"}

def btn(bg: str = BORDER, fg: str = TEXT, extra: dict = None) -> dict:
    """Stilul standard pentru html.Button."""
    s = {"background": bg, "color": fg, "border": "none",
         "borderRadius": "6px", "padding": "6px 14px",
         "cursor": "pointer", "fontSize": "12px", "fontWeight": "600"}
    if extra:
        s.update(extra)
    return s

def card(continut, extra: dict = None):
    """Wrapper card cu fundal CARD si border-radius."""
    s = {"backgroundColor": CARD, "borderRadius": "10px",
         "padding": "16px", "marginBottom": "14px"}
    if extra:
        s.update(extra)
    return html.Div(continut, style=s)

def badge_sev(sev: str):
    """Badge colorat pentru severitate."""
    c = SEV_CULORI.get(sev, MUTED)
    return html.Span(sev, style={
        "backgroundColor": c + "22", "color": c,
        "border": f"1px solid {c}55", "borderRadius": "4px",
        "padding": "2px 7px", "fontSize": "11px",
        "fontWeight": "700", "marginLeft": "6px",
    })

def sectiune_titlu(text: str):
    """Titlu de sectiune (uppercase, mic)."""
    return html.P(text, style={
        "color": MUTED, "fontSize": "11px", "margin": "0 0 8px 0",
        "fontWeight": "600", "textTransform": "uppercase",
        "letterSpacing": "0.08em",
    })

def style_header_tabel() -> dict:
    return {"backgroundColor": DARK, "color": MUTED,
            "fontWeight": "600", "border": "none", "fontSize": "12px"}

def style_cell_tabel() -> dict:
    return {"backgroundColor": CARD, "color": TEXT,
            "border": f"1px solid {BORDER}", "fontSize": "12px",
            "padding": "5px 10px", "fontFamily": "monospace"}

def style_header_tabel2() -> dict:
    return {"backgroundColor": DARK2, "color": MUTED,
            "fontWeight": "600", "border": "none", "fontSize": "12px"}

def style_cell_tabel2() -> dict:
    return {"backgroundColor": DARK2, "color": TEXT,
            "border": f"1px solid {BORDER}", "fontSize": "12px",
            "padding": "4px 10px", "fontFamily": "monospace"}

STYLE_DATA_COND_PROTO = [
    {"if": {"filter_query": '{protocol} = "TCP"'},  "color": "#7dd3fc"},
    {"if": {"filter_query": '{protocol} = "UDP"'},  "color": "#86efac"},
    {"if": {"filter_query": '{protocol} = "OTHER"'},"color": "#d8b4fe"},
]

# Stiluri tab-uri (reutilizate in mai multe locuri)
TAB_STYLE     = {"backgroundColor": CARD,  "color": MUTED,  "border": "none",
                 "padding": "8px 18px", "fontSize": "13px"}
TAB_SEL_STYLE = {"backgroundColor": DARK,  "color": TEXT,
                 "borderBottom": f"2px solid {ACCENT}55",
                 "padding": "8px 18px", "fontSize": "13px"}
MAIN_TAB_STYLE     = {"backgroundColor": DARK2, "color": MUTED, "border": "none",
                      "padding": "12px 28px", "fontSize": "14px", "fontWeight": "600"}
MAIN_TAB_SEL_STYLE = {"backgroundColor": CARD,  "color": TEXT,
                      "borderBottom": f"2px solid {ACCENT}",
                      "padding": "12px 28px", "fontSize": "14px", "fontWeight": "600"}

# ─── ML BUTTON HELPERS ────────────────────────────────────────────────────────
# Trei clase vizuale pentru butoanele ML: verde (actiune pozitiva),
# rosu (actiune distructiva/oprire), gri (dezactivat).

def btn_ml_verde(extra: dict = None) -> dict:
    """Buton ML activ — actiune pozitiva (pornire, activare, reantreneaza)."""
    s = {
        "background": "#166534", "color": "#86efac",
        "border": "none", "borderRadius": "6px",
        "padding": "7px 16px", "cursor": "pointer",
        "fontSize": "12px", "fontWeight": "600",
        "transition": "opacity .15s",
    }
    if extra:
        s.update(extra)
    return s

def btn_ml_rosu(extra: dict = None) -> dict:
    """Buton ML activ — actiune distructiva (oprire, stergere, dezactivare)."""
    s = {
        "background": "#7f1d1d", "color": "#fca5a5",
        "border": "none", "borderRadius": "6px",
        "padding": "7px 16px", "cursor": "pointer",
        "fontSize": "12px", "fontWeight": "600",
        "transition": "opacity .15s",
    }
    if extra:
        s.update(extra)
    return s

def btn_ml_gri(extra: dict = None) -> dict:
    """Buton ML dezactivat — nu poate fi apasat."""
    s = {
        "background": "#1e293b", "color": "#475569",
        "border": f"1px solid {BORDER}", "borderRadius": "6px",
        "padding": "7px 16px", "cursor": "not-allowed",
        "fontSize": "12px", "fontWeight": "600",
        "opacity": "0.6",
    }
    if extra:
        s.update(extra)
    return s


def grup_input_validat(
    id_input: str,
    tip: str = "text",          # "text" | "number"
    placeholder: str = "",
    stil_extra: dict = None,
    regex: str = None,          # regex JS (string) pentru filtrare caractere
    mesaj_eroare: str = "",
    debounce: bool = True,
    **kwargs_input,
):
    """
    Returnează un html.Div cu:
      - dcc.Input (cu data-regex și data-eroare pentru clientside)
      - html.Div pentru mesajul de eroare (popup mic)
    """
    stil_input = inp(stil_extra or {})
    return html.Div([
        dcc.Input(
            id=id_input,
            type=tip,
            placeholder=placeholder,
            debounce=debounce,
            style=stil_input,
            **({'data-regex': regex} if regex else {}),
            **kwargs_input,
        ),
        html.Div(
            id=f"{id_input}-eroare",
            style={
                "position":        "absolute",
                "top":             "calc(100% + 2px)",
                "left":            "0",
                "backgroundColor": "#1e1a10",
                "color":           "#fbbf24",
                "border":          "1px solid #92400e",
                "borderRadius":    "5px",
                "padding":         "4px 10px",
                "fontSize":        "11px",
                "zIndex":          "999",
                "whiteSpace":      "nowrap",
                "display":         "none",   # ascuns implicit
                "boxShadow":       "0 4px 12px rgba(0,0,0,0.5)",
                "pointerEvents":   "none",
            },
            children=mesaj_eroare,
        ),
    ], style={"position": "relative", "display": "inline-block"})