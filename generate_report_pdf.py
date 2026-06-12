"""Generate PROJECT_REPORT.pdf from PROJECT_REPORT.md using fpdf2."""
import re
from pathlib import Path
from fpdf import FPDF
from fpdf.enums import XPos, YPos

# ── Color palette ─────────────────────────────────────────────────────────────
NAVY   = (15,  23,  42)
BLUE   = (30,  64, 175)
LIGHT  = (219, 234, 254)
GRAY   = (100, 116, 139)
WHITE  = (255, 255, 255)
GREEN  = (5,  150, 105)
RED    = (185,  28,  28)

MD_PATH  = Path(__file__).parent / "PROJECT_REPORT.md"
OUT_PATH = Path(__file__).parent / "PROJECT_REPORT.pdf"

_UNICODE_MAP = {
    '—': '--',  '–': '-',   '‘': "'",  '’': "'",
    '“': '"',   '”': '"',   '•': '-',  '…': '...',
    '·': '-',   ' ': ' ',   '→': '->',  '←': '<-',
    '≤': '<=',  '≥': '>=',  '×': 'x',   '°': ' deg',
}

def _safe(text: str) -> str:
    """Replace non-latin-1 characters with safe ASCII equivalents."""
    for ch, repl in _UNICODE_MAP.items():
        text = text.replace(ch, repl)
    return text.encode('latin-1', errors='replace').decode('latin-1')


class ReportPDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=22)
        self.set_margins(20, 20, 20)
        self._toc: list[tuple[int, str, int]] = []   # (level, title, page)
        self._in_code  = False
        self._code_buf = []
        self._in_table = False
        self._table_rows: list[list[str]] = []
        self._table_headers: list[str] = []

    # ── Page decorations ───────────────────────────────────────────────────────
    def header(self):
        if self.page_no() <= 2:
            return
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*GRAY)
        self.cell(0, 7, "IntraComms - Project Report", align="L",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(*GRAY)
        self.set_line_width(0.2)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(3)
        self.set_text_color(0, 0, 0)

    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-14)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*GRAY)
        self.cell(0, 8, f"Page {self.page_no()}", align="C")

    # ── Typography helpers ────────────────────────────────────────────────────
    def h1(self, text: str):
        text = self._to_latin1(text)
        self.ln(5)
        self.set_fill_color(*NAVY)
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 13)
        self.cell(0, 9, f"  {text}", fill=True,
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(3)
        self.set_text_color(0, 0, 0)

    def h2(self, text: str):
        text = self._to_latin1(text)
        self.ln(4)
        self.set_text_color(*BLUE)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 7, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(*BLUE)
        self.set_line_width(0.5)
        self.line(self.l_margin, self.get_y(), self.l_margin + 55, self.get_y())
        self.ln(3)
        self.set_text_color(0, 0, 0)

    def h3(self, text: str):
        text = self._to_latin1(text)
        self.ln(3)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*NAVY)
        self.cell(0, 6, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)
        self.set_text_color(0, 0, 0)

    def body(self, text: str, indent: int = 0):
        text = self._to_latin1(text)
        self.set_font("Helvetica", "", 10)
        self.set_text_color(0, 0, 0)
        x = self.l_margin + indent
        w = self.w - self.l_margin - self.r_margin - indent
        self.set_x(x)
        self.multi_cell(w, 5.5, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def bullet(self, text: str, indent: int = 4):
        text = self._to_latin1(text)
        self.set_font("Helvetica", "", 10)
        self.set_text_color(0, 0, 0)
        w = self.w - self.l_margin - self.r_margin - indent - 5
        self.set_x(self.l_margin + indent)
        self.cell(5, 5.5, "-")
        self.multi_cell(w, 5.5, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def sub_bullet(self, text: str):
        self.bullet(text, indent=10)

    def hr(self):
        self.ln(2)
        self.set_draw_color(*GRAY)
        self.set_line_width(0.2)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(4)

    def code(self, text: str):
        self.set_fill_color(240, 244, 248)
        self.set_draw_color(200, 210, 220)
        self.set_line_width(0.3)
        self.set_font("Courier", "", 8)
        self.set_text_color(20, 20, 20)
        lines = text.split("\n")
        w   = self.w - self.l_margin - self.r_margin
        pad = 3
        lh  = 4.5
        total_h = len(lines) * lh + pad * 2
        y0 = self.get_y()
        # check page break
        if y0 + total_h > self.h - self.b_margin:
            self.add_page()
            y0 = self.get_y()
        self.rect(self.l_margin, y0, w, total_h, style="DF")
        for i, line in enumerate(lines):
            self.set_xy(self.l_margin + pad, y0 + pad + i * lh)
            self.cell(w - pad * 2, lh, line)
        self.set_xy(self.l_margin, y0 + total_h)
        self.ln(3)
        self.set_text_color(0, 0, 0)

    def table(self, headers: list, rows: list, col_widths: list = None):
        w   = self.w - self.l_margin - self.r_margin
        n   = len(headers)
        if col_widths is None:
            col_widths = [w / n] * n

        # Normalise ragged rows to exactly n cells so per-column indexing is safe
        # (a stray cell would otherwise overrun col_widths).
        rows = [list(r)[:n] + [""] * (n - len(r)) for r in rows]

        row_h = 7
        # header
        self.set_fill_color(*NAVY)
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 9)
        x = self.l_margin
        for i, h in enumerate(headers):
            self.set_xy(x, self.get_y())
            self.cell(col_widths[i], row_h, f"  {h}", fill=True, border=0)
            x += col_widths[i]
        self.ln(row_h)

        headers = [self._to_latin1(str(h)) for h in headers]
        rows = [[self._to_latin1(str(c)) for c in r] for r in rows]
        self.set_font("Helvetica", "", 9)
        for ridx, row in enumerate(rows):
            # compute tallest cell height
            needed = row_h
            for ci, cell in enumerate(row):
                sw = self.get_string_width(str(cell))
                lines_est = int(sw / max(col_widths[ci] - 6, 1)) + 1
                needed = max(needed, lines_est * 5 + 2)

            # page break guard
            if self.get_y() + needed > self.h - self.b_margin:
                self.add_page()
                # re-draw header on new page
                self.set_fill_color(*NAVY)
                self.set_text_color(*WHITE)
                self.set_font("Helvetica", "B", 9)
                x = self.l_margin
                for i, h in enumerate(headers):
                    self.set_xy(x, self.get_y())
                    self.cell(col_widths[i], row_h, f"  {h}", fill=True, border=0)
                    x += col_widths[i]
                self.ln(row_h)
                self.set_font("Helvetica", "", 9)

            fill = ridx % 2 == 1
            self.set_fill_color(*LIGHT)
            self.set_text_color(0, 0, 0)
            x = self.l_margin
            y = self.get_y()
            for ci, cell in enumerate(row):
                self.set_xy(x, y)
                self.multi_cell(col_widths[ci], needed, f"  {cell}",
                                fill=fill, border=0,
                                new_x=XPos.RIGHT, new_y=YPos.TOP)
                x += col_widths[ci]
            self.set_xy(self.l_margin, y + needed)
        self.ln(4)

    # ── Markdown parser ───────────────────────────────────────────────────────
    def _to_latin1(self, text: str) -> str:
        return _safe(text)

    def _strip_inline(self, text: str) -> str:
        """Strip inline markdown markers: **bold**, *italic*, `code`, [text](url)."""
        text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
        text = re.sub(r'\*(.+?)\*',     r'\1', text)
        text = re.sub(r'`(.+?)`',        r'\1', text)
        text = re.sub(r'\[(.+?)\]\(.+?\)', r'\1', text)
        return self._to_latin1(text)

    def _flush_table(self):
        if not self._table_headers:
            return
        # Parse column widths from alignment row (we just distribute evenly)
        filtered = [r for r in self._table_rows if not re.match(r'^\|[-: |]+\|$', r[0] if r else '')]
        if filtered:
            n = len(self._table_headers)
            avail = self.w - self.l_margin - self.r_margin
            col_w = [avail / n] * n
            self.table(self._table_headers, filtered, col_w)
        self._table_headers = []
        self._table_rows = []
        self._in_table = False

    def render_md(self, md_text: str):
        """Parse markdown and render to PDF."""
        lines = md_text.splitlines()
        i = 0
        while i < len(lines):
            raw = lines[i]
            stripped = raw.strip()

            # ── Fenced code block ──────────────────────────────────────────────
            if stripped.startswith("```"):
                if self._in_table:
                    self._flush_table()
                buf = []
                i += 1
                while i < len(lines):
                    if lines[i].strip().startswith("```"):
                        i += 1
                        break
                    buf.append(lines[i])
                    i += 1
                self.code(self._to_latin1("\n".join(buf)))
                continue

            # ── Horizontal rule ────────────────────────────────────────────────
            if re.match(r'^---+$', stripped):
                if self._in_table:
                    self._flush_table()
                self.hr()
                i += 1
                continue

            # ── Headings ───────────────────────────────────────────────────────
            if stripped.startswith("# ") and not stripped.startswith("## "):
                if self._in_table:
                    self._flush_table()
                title = self._strip_inline(stripped[2:].strip())
                # TOC level 1
                self._toc.append((1, title, self.page_no()))
                self.h1(title)
                i += 1
                continue

            if stripped.startswith("## ") and not stripped.startswith("### "):
                if self._in_table:
                    self._flush_table()
                title = self._strip_inline(stripped[3:].strip())
                self._toc.append((2, title, self.page_no()))
                self.h2(title)
                i += 1
                continue

            if stripped.startswith("### "):
                if self._in_table:
                    self._flush_table()
                title = self._strip_inline(stripped[4:].strip())
                self.h3(title)
                i += 1
                continue

            # ── Markdown table row ─────────────────────────────────────────────
            if stripped.startswith("|") and stripped.endswith("|"):
                cells = [c.strip() for c in stripped.strip("|").split("|")]
                if not self._in_table:
                    # First row = headers
                    self._table_headers = [self._strip_inline(c) for c in cells]
                    self._in_table = True
                else:
                    # Skip alignment rows (---)
                    if not all(re.match(r'^[-:]+$', c.replace(' ', '')) for c in cells if c):
                        self._table_rows.append([self._strip_inline(c) for c in cells])
                i += 1
                continue
            else:
                # Non-table line — flush pending table
                if self._in_table:
                    self._flush_table()

            # ── Bullet / numbered list ─────────────────────────────────────────
            m = re.match(r'^(\s*)[-*]\s+(.*)', raw)
            if m:
                indent_lvl = len(m.group(1))
                text = self._strip_inline(m.group(2))
                if indent_lvl >= 2:
                    self.sub_bullet(text)
                else:
                    self.bullet(text)
                i += 1
                continue

            m = re.match(r'^(\s*)\d+\.\s+(.*)', raw)
            if m:
                text = self._strip_inline(m.group(2))
                self.bullet(text)
                i += 1
                continue

            # ── Blank line ─────────────────────────────────────────────────────
            if not stripped:
                self.ln(2)
                i += 1
                continue

            # ── Plain paragraph text ───────────────────────────────────────────
            self.body(self._strip_inline(stripped))
            i += 1


# ── Cover page ────────────────────────────────────────────────────────────────
def build_cover(pdf: ReportPDF):
    pdf.add_page()
    # Full-page navy background
    pdf.set_fill_color(*NAVY)
    pdf.rect(0, 0, pdf.w, pdf.h, style="F")

    # Title block
    pdf.set_y(50)
    pdf.set_font("Helvetica", "B", 30)
    pdf.set_text_color(*WHITE)
    pdf.cell(0, 14, "IntraComms", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(147, 197, 253)
    pdf.cell(0, 9, "LAN-Based Internal Communication System",
             align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.ln(6)
    pdf.set_draw_color(59, 130, 246)
    pdf.set_line_width(1)
    pdf.line(35, pdf.get_y(), pdf.w - 35, pdf.get_y())
    pdf.ln(10)

    details = [
        ("Project Report", "Final Year Project - Semester 3"),
        ("Author",         "Ibrahim Habib"),
        ("Student ID",     "LC000111000882"),
        ("Institution",    "Lincoln University College"),
        ("Program",        "Computer Software Engineering"),
        ("Date",           "June 2026"),
    ]
    for k, v in details:
        pdf.set_text_color(147, 197, 253)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_x(35)
        pdf.cell(45, 8, k + ":")
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(*WHITE)
        pdf.cell(0, 8, v, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Badge row
    pdf.ln(14)
    badges = [("Flask", BLUE), ("Socket.IO", GREEN), ("AES-256-GCM", RED),
              ("SQLite", GRAY), ("ECDH P-256", (109, 40, 217))]
    total_w = sum(pdf.get_string_width(t) + 12 for t, _ in badges) + (len(badges) - 1) * 4
    pdf.set_x((pdf.w - total_w) / 2)
    for text, color in badges:
        pdf.set_fill_color(*color)
        pdf.set_text_color(*WHITE)
        pdf.set_font("Helvetica", "B", 8)
        bw = pdf.get_string_width(text) + 12
        pdf.cell(bw, 7, text, fill=True)
        pdf.cell(4, 7, "")
    pdf.ln(8)

    # Footer note
    pdf.set_y(-20)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(100, 130, 180)
    pdf.cell(0, 6, "Submitted as Final Project - Computer Software Engineering Semester 3",
             align="C")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    md_text = MD_PATH.read_text(encoding="utf-8")

    # Strip YAML front-matter (the big H1 title block at top)
    # We keep everything after the first blank line following the title
    md_text = re.sub(r'^# IntraComms.*\n', '', md_text, count=1)

    pdf = ReportPDF()

    # Cover
    build_cover(pdf)

    # Content — start on page 2
    pdf.add_page()
    pdf.render_md(md_text)

    pdf.output(str(OUT_PATH))
    print(f"PDF written to: {OUT_PATH}")
    print(f"Pages: {pdf.page}")


if __name__ == "__main__":
    main()
