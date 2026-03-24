#!/usr/bin/env python3
"""
router_audit.py - Auditoría completa de router para laboratorio Kali
Objetivo: 192.168.0.1 | Autor: para uso educativo / laboratorio propio
Uso: sudo python3 router_audit.py [--target 192.168.0.1] [--mode full|speed|security]
"""

import subprocess
import socket
import time
import sys
import re
import json
import argparse
import urllib.request
import urllib.error
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURACIÓN
# ─────────────────────────────────────────────────────────────────────────────
TARGET       = "192.168.0.1"
EXTERNAL_IPS = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]  # Para medir latencia ISP
PING_COUNT   = 10
REPORT_FILE  = f"Crypt3cho_RouterAudit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

COLORS = {
    "ok":    "\033[92m",  # verde
    "warn":  "\033[93m",  # amarillo
    "bad":   "\033[91m",  # rojo
    "info":  "\033[96m",  # cian
    "bold":  "\033[1m",
    "reset": "\033[0m",
}

def c(color, text):
    return f"{COLORS.get(color,'')}{text}{COLORS['reset']}"

def section(title):
    print(f"\n{c('bold','═'*60)}")
    print(f"{c('bold', f'  {title}')}")
    print(f"{c('bold','═'*60)}")

def run(cmd, timeout=15):
    """Ejecuta un comando de shell y devuelve stdout."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "TIMEOUT", 1
    except Exception as e:
        return str(e), 1

results = {}  # acumula todo para el JSON final


import os
import tempfile

# ══════════════════════════════════════════════════════════════
# PDF — GENERADOR ESTILO CRYPT3CHO
# ══════════════════════════════════════════════════════════════
def _s(text):
    if not text: return ''
    repl = {
        '—':'--','–':'-','‘':"'",'’':"'",
        '“':'"','”':'"','•':'-','…':'...',
        ' ':' ','→':'->','⚠':'(!)','✓':'OK',
    }
    for ch, r in repl.items():
        text = text.replace(ch, r)
    return text.encode('latin-1', errors='replace').decode('latin-1')

def generate_charts(results, target):
    charts = []
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        return charts

    BG    = '#0B1120'; CYAN = '#00FF9C'; RED = '#FF4C4C'
    AMB   = '#FFB800'; BLUE = '#4CA3FF'; GRAY = '#4A7AAA'; WHITE = '#E8F0FF'

    # Grafica 1: Latencia comparativa
    lat = results.get('latency', {})
    lat_data = {}
    r_lat = lat.get('router', {})
    if isinstance(r_lat, dict) and r_lat.get('avg_ms'):
        lat_data[f'Router\n({target})'] = float(r_lat['avg_ms'])
    ext = lat.get('external', {})
    if isinstance(ext, dict):
        for ip, v in ext.items():
            if isinstance(v, dict) and v.get('avg_ms'):
                lat_data[ip.split('(')[0].strip()[:12]] = float(v['avg_ms'])

    if lat_data:
        fig, ax = plt.subplots(figsize=(10, 4.5), facecolor=BG)
        ax.set_facecolor('#0F1A2E')
        labels = list(lat_data.keys())
        vals   = list(lat_data.values())
        colors = [CYAN if v < 10 else AMB if v < 50 else RED for v in vals]
        bars = ax.bar(labels, vals, color=colors, width=0.5, zorder=3)
        ax.grid(axis='y', color='#1E3A5F', linewidth=0.8)
        for spine in ax.spines.values(): spine.set_color('#1E3A5F')
        ax.tick_params(colors=GRAY, labelsize=8)
        ax.set_ylabel('ms', color=GRAY, fontsize=9)
        ax.set_title('LATENCIA POR DESTINO', color=WHITE, fontsize=11, fontweight='bold', pad=12)
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.3,
                    f'{v:.1f}ms', ha='center', va='bottom', color=WHITE, fontsize=8, fontweight='bold')
        ax.axhline(y=15, color=AMB, linewidth=1, linestyle='--', alpha=0.6)
        ax.text(max(0, len(labels)-0.5), 16, 'limite ok', color=AMB, fontsize=7)
        fig.patch.set_facecolor(BG)
        plt.tight_layout()
        p = tempfile.mktemp(suffix='_lat.png')
        fig.savefig(p, dpi=150, bbox_inches='tight', facecolor=BG)
        plt.close(fig)
        charts.append(('LATENCIA POR DESTINO (ms)', p))

    # Grafica 2: DNS benchmark
    dns = results.get('dns', {})
    dns_data = {}
    for k, v in dns.items():
        if isinstance(v, dict) and v.get('avg_ms'):
            dns_data[k[:22]] = float(v['avg_ms'])
    if dns_data:
        fig, ax = plt.subplots(figsize=(10, 4.5), facecolor=BG)
        ax.set_facecolor('#0F1A2E')
        labels = list(dns_data.keys())
        vals   = list(dns_data.values())
        colors = [CYAN if v < 50 else AMB if v < 150 else RED for v in vals]
        bars = ax.barh(labels, vals, color=colors, height=0.5, zorder=3)
        ax.grid(axis='x', color='#1E3A5F', linewidth=0.8)
        for spine in ax.spines.values(): spine.set_color('#1E3A5F')
        ax.tick_params(colors=GRAY, labelsize=8)
        ax.set_xlabel('ms', color=GRAY, fontsize=9)
        ax.set_title('RENDIMIENTO DNS (ms)', color=WHITE, fontsize=11, fontweight='bold', pad=12)
        for bar, v in zip(bars, vals):
            ax.text(v+1, bar.get_y()+bar.get_height()/2,
                    f'{v:.1f}ms', va='center', color=WHITE, fontsize=8)
        fig.patch.set_facecolor(BG)
        plt.tight_layout()
        p = tempfile.mktemp(suffix='_dns.png')
        fig.savefig(p, dpi=150, bbox_inches='tight', facecolor=BG)
        plt.close(fig)
        charts.append(('RENDIMIENTO DNS', p))

    # Grafica 3: Radar de seguridad
    import math
    ports_out = results.get('ports', {}).get('nmap_common', '')
    danger = sum(1 for p in ['23/tcp','21/tcp','3389/tcp'] if p in ports_out and 'open' in ports_out)
    s_ports   = max(0, 100 - danger * 40)
    cred = results.get('credentials', {}).get('default_cred_found')
    s_creds   = 0 if cred else 100
    upnp = results.get('upnp', {}).get('upnp_1900', 'closed')
    s_upnp    = 0 if upnp == 'open' else 100
    wp = results.get('web_panel', {})
    hdr_ok = sum(50 for s in ['http','https']
                 if 'AUSENTE' not in str(wp.get(s, {}).get('x_frame','AUSENTE')))
    s_headers = min(100, hdr_ok)
    sig_r = results.get('wifi', {}).get('signal_dbm', 'N/A')
    try:    s_signal = 100 if int(sig_r) > -60 else 70 if int(sig_r) > -70 else 30
    except: s_signal = 50

    scores = [s_ports, s_creds, s_upnp, s_headers, s_signal]
    axes_lbl = ['Puertos\nCerrados','Sin Creds\nDefault',
                'UPnP\nDesact.','Headers\nHTTP','Signal\nWiFi']
    N = len(axes_lbl)
    angles = [n / float(N) * 2 * math.pi for n in range(N)] + [0]
    vals_r = scores + [scores[0]]

    fig, ax = plt.subplots(figsize=(7, 7), subplot_kw=dict(polar=True), facecolor=BG)
    ax.set_facecolor('#0F1A2E')
    ax.set_ylim(0, 100)
    ax.set_yticks([20,40,60,80,100])
    ax.set_yticklabels(['20','40','60','80','100'], fontsize=6, color=GRAY)
    ax.grid(color='#1E3A5F', linewidth=0.8)
    ax.spines['polar'].set_color('#1E3A5F')
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(axes_lbl, fontsize=8, color='#8BAFD4')
    ax.set_theta_offset(math.pi / 2)
    ax.set_theta_direction(-1)
    avg = sum(scores) / len(scores)
    col = CYAN if avg >= 70 else AMB if avg >= 40 else RED
    ax.plot(angles, vals_r, color=col, linewidth=2)
    ax.fill(angles, vals_r, color=col, alpha=0.25)
    ax.scatter(angles[:-1], scores, color=col, s=40, zorder=4, edgecolors='white', linewidths=0.6)
    nivel = 'BUENO' if avg >= 70 else 'ATENCION' if avg >= 40 else 'CRITICO'
    fig.text(0.5, 0.97, 'PERFIL DE SEGURIDAD DEL ROUTER',
             ha='center', va='top', fontsize=12, color=WHITE, fontweight='bold')
    fig.text(0.5, 0.935, f'Score promedio: {avg:.0f}/100  [{nivel}]',
             ha='center', va='top', fontsize=9, color=col)
    fig.patch.set_facecolor(BG)
    plt.tight_layout(rect=[0, 0, 1, 0.92])
    p = tempfile.mktemp(suffix='_radar.png')
    fig.savefig(p, dpi=150, bbox_inches='tight', facecolor=BG)
    plt.close(fig)
    charts.append(('PERFIL DE SEGURIDAD DEL ROUTER', p))
    return charts


def generate_pdf(results, filename):
    try:
        from fpdf import FPDF, XPos, YPos
    except ImportError:
        print("  fpdf2 no instalado -- pip install fpdf2 --break-system-packages")
        return False

    NAVY_C=(15,40,80); WHITE_C=(255,255,255); RED_C=(180,30,30)
    GREEN_C=(30,140,70); AMB_C=(180,130,0); GRAY_D=(50,60,80)
    GRAY_M=(120,130,145); ACCENT=(0,120,200)
    PAGE_BOTTOM=276; SCAN_ID=datetime.now().strftime('%Y%m%d%H%M')
    target = results.get('target', TARGET)

    class RouterPDF(FPDF):
        def header(self):
            self.set_fill_color(*NAVY_C); self.rect(0,0,210,26,'F')
            self.set_fill_color(*ACCENT); self.rect(0,26,210,2,'F')
            self.set_text_color(*WHITE_C); self.set_font('Arial','B',11)
            self.set_xy(12,5); self.cell(130,7,_s('AUDITORIA DE ROUTER -- ROUTERGUARD'))
            self.set_font('Arial',size=7); self.set_text_color(180,200,240)
            self.set_xy(12,14)
            self.cell(130,5,_s(f'Target: {target}  |  {datetime.now().strftime("%Y-%m-%d %H:%M")}'))
            self.set_font('Arial','B',10); self.set_text_color(*WHITE_C)
            self.set_xy(150,5); self.cell(50,6,'CRYPT3CHO',0,0,'R')
            self.set_font('Arial',size=7); self.set_text_color(180,200,240)
            self.set_xy(150,12); self.cell(50,5,'RouterGuard v1.1',0,0,'R')
            self.set_xy(150,18); self.cell(50,5,f'ID: {SCAN_ID}',0,0,'R')
            self.ln(8)

        def footer(self):
            self.set_y(-16)
            self.set_fill_color(235,238,245); self.rect(0,self.get_y(),210,16,'F')
            self.set_fill_color(*ACCENT); self.rect(0,self.get_y(),210,0.8,'F')
            self.set_font('Arial',size=7); self.set_text_color(*GRAY_M)
            self.set_xy(12,self.get_y()+4)
            self.cell(130,5,_s('CRYPT3CHO | crypt3cho.com | Documento Confidencial'))
            self.cell(0,5,f'Pagina {self.page_no()}',0,0,'R')

        def _cy(self,n=8):
            if self.get_y()+n > PAGE_BOTTOM: self.add_page()

        def section_title(self, title):
            self._cy(18); self.ln(2); y=self.get_y()
            self.set_fill_color(*NAVY_C); self.rect(12,y,186,9,'F')
            self.set_fill_color(*ACCENT); self.rect(12,y,3,9,'F')
            self.set_font('Arial','B',9); self.set_text_color(*WHITE_C)
            self.set_xy(18,y); self.cell(0,9,_s(title)); self.ln(1)

        def data_row(self, label, value, nivel=None):
            RCFG = {
                'CRITICO':(RED_C,(255,242,242),'CRITICO'),
                'ALTO':((180,80,0),(255,248,235),'ALTO'),
                'MEDIO':(AMB_C,(255,252,220),'MEDIO'),
                'BAJO':(GREEN_C,(240,250,243),'OK'),
                'INFO':(GRAY_M,WHITE_C,'INFO'),
            }
            cfg=RCFG.get(nivel,(GRAY_D,WHITE_C,''))
            self._cy(8); ry=self.get_y()
            self.set_fill_color(*cfg[1]); self.rect(12,ry,186,7,'F')
            self.set_font('Arial','B',7.5); self.set_text_color(*NAVY_C)
            self.set_x(14); self.cell(55,7,_s(str(label)[:30]))
            if nivel and cfg[2]:
                bx=self.get_x()
                self.set_fill_color(*cfg[0]); self.rect(bx,ry+1.5,22,4,'F')
                self.set_font('Arial','B',6); self.set_text_color(*WHITE_C)
                self.set_xy(bx,ry+1); self.cell(22,5,cfg[2],0,0,'C')
                self.set_xy(bx+24,ry)
            self.set_font('Arial',size=7.5); self.set_text_color(*GRAY_D)
            self.multi_cell(0,7,_s(f'  {str(value)[:180]}'),
                            new_x=XPos.LMARGIN,new_y=YPos.NEXT)
            self.set_draw_color(220,225,235)
            self.line(12,self.get_y(),198,self.get_y())

    pdf = RouterPDF()
    pdf.set_auto_page_break(auto=False)
    pdf.add_page()

    # Seccion 1: Red
    pdf.section_title('1. INFORMACION DE RED')
    net = results.get('network_info', {})
    pdf.data_row('TARGET / ROUTER', target)
    pdf.data_row('FECHA SCAN', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    pdf.data_row('OPERADOR', 'CRYPT3CHO RouterGuard v1.1')
    if net.get('gateway'): pdf.data_row('GATEWAY', net['gateway'])
    if net.get('dns'):     pdf.data_row('DNS CONFIGURADO', net['dns'][:80])

    # Seccion 2: Resumen
    pdf.section_title('2. RESUMEN EJECUTIVO')
    issues   = results.get('summary',{}).get('issues',[])
    suggests = results.get('summary',{}).get('suggestions',[])
    nivel_g  = 'CRITICO' if len(issues)>=3 else 'ALTO' if len(issues)>=2 else 'MEDIO' if issues else 'BAJO'
    pdf.data_row('NIVEL GENERAL', nivel_g, nivel_g)
    pdf.data_row('PROBLEMAS', str(len(issues)), 'CRITICO' if issues else 'BAJO')
    for iss in issues:
        pdf.data_row('  [!]', iss, 'ALTO')
    if not issues:
        pdf.data_row('ESTADO', 'No se detectaron problemas criticos', 'BAJO')

    # Seccion 3: Latencia
    pdf.section_title('3. LATENCIA Y CONECTIVIDAD')
    lat = results.get('latency', {})
    r_lat = lat.get('router', {})
    if isinstance(r_lat, dict) and r_lat.get('avg_ms') is not None:
        avg = float(r_lat['avg_ms'])
        nivel = 'BAJO' if avg<10 else 'MEDIO' if avg<30 else 'ALTO'
        pdf.data_row(f'PING ROUTER ({target})',
            f"avg {avg:.1f}ms  min {r_lat.get('min_ms',0):.1f}ms  "
            f"max {r_lat.get('max_ms',0):.1f}ms  perdida {r_lat.get('loss_pct',0):.0f}%", nivel)
    ext = lat.get('external', {})
    if isinstance(ext, dict):
        for dest, v in ext.items():
            if isinstance(v,dict) and v.get('avg_ms') is not None:
                avg_e = float(v['avg_ms'])
                pdf.data_row(f'PING {dest[:20]}', f"avg {avg_e:.1f}ms",
                             'BAJO' if avg_e<50 else 'MEDIO' if avg_e<150 else 'ALTO')

    # Seccion 4: Puertos
    pdf.section_title('4. PUERTOS ABIERTOS')
    DANGER_MAP = {
        '23/tcp':  ('TELNET','CRITICO','Sin cifrado -- credenciales en texto plano'),
        '21/tcp':  ('FTP','ALTO','Transferencia sin cifrado'),
        '3389/tcp':('RDP','ALTO','Escritorio remoto -- vector ransomware'),
        '8080/tcp':('HTTP-ALT','MEDIO','Panel web alternativo'),
        '1900/tcp':('UPnP','MEDIO','Universal Plug and Play'),
    }
    ports_out = results.get('ports',{}).get('nmap_common','')
    found_d = False
    for pstr,(name,nivel,desc) in DANGER_MAP.items():
        if pstr in ports_out and 'open' in ports_out:
            pdf.data_row(f'{name} ({pstr})', desc, nivel); found_d=True
    if not found_d:
        pdf.data_row('RESULTADO','No se detectaron puertos peligrosos','BAJO')
    if ports_out:
        pdf.ln(2); pdf.set_font('Courier',size=6); pdf.set_text_color(*GRAY_M)
        for line in ports_out.splitlines()[:20]:
            pdf._cy(4); pdf.set_x(14); pdf.cell(0,4,_s(line[:100])); pdf.ln()

    # Seccion 5: Credenciales
    pdf.section_title('5. CREDENCIALES POR DEFECTO')
    cred = results.get('credentials',{}).get('default_cred_found')
    if cred:
        pdf.data_row('CREDENCIAL ENCONTRADA',
            f"{cred['user']}:{cred['pass'] or '(vacia)'}",'CRITICO')
        pdf.data_row('ACCION','Cambiar contrasena del router INMEDIATAMENTE','CRITICO')
    else:
        pdf.data_row('RESULTADO','Sin credenciales por defecto detectadas','BAJO')

    # Seccion 6: Panel Web
    pdf.section_title('6. PANEL WEB DEL ROUTER')
    wp = results.get('web_panel',{})
    for scheme in ['http','https']:
        sd = wp.get(scheme,{})
        if isinstance(sd,dict) and 'status' in sd:
            pdf.data_row(f'{scheme.upper()} (Status {sd["status"]})',
                f"Server: {sd.get('server','N/A')}  X-Frame: {sd.get('x_frame','N/A')}",
                'INFO' if sd['status']==200 else 'MEDIO')
    if wp.get('html_info'):
        pdf.data_row('INFO HTML',wp['html_info'][:120],'INFO')

    # Seccion 7: WiFi
    pdf.section_title('7. SEGURIDAD WiFi')
    wifi = results.get('wifi',{})
    sig_raw = wifi.get('signal_dbm','N/A')
    if sig_raw != 'N/A':
        try:
            sig_db=int(sig_raw)
            nivel_sig='BAJO' if sig_db>-60 else 'MEDIO' if sig_db>-75 else 'ALTO'
            q='Excelente' if sig_db>-60 else 'Buena' if sig_db>-70 else 'Debil'
            pdf.data_row('NIVEL DE SEÑAL',f'{sig_raw} dBm -- {q}',nivel_sig)
        except: pass

    # Seccion 8: DNS
    pdf.section_title('8. RENDIMIENTO DNS')
    dns = results.get('dns',{})
    for dname,v in dns.items():
        if isinstance(v,dict) and v.get('avg_ms') is not None:
            avg_d=float(v['avg_ms'])
            pdf.data_row(dname[:30],f'{avg_d:.1f}ms',
                         'BAJO' if avg_d<50 else 'MEDIO' if avg_d<200 else 'ALTO')

    # Seccion 9: UPnP
    pdf.section_title('9. UPnP')
    upnp=results.get('upnp',{})
    if upnp.get('upnp_1900')=='open':
        pdf.data_row('UPnP ACTIVO','Puerto 1900 abierto -- vector de ataque','ALTO')
    else:
        pdf.data_row('UPnP','Puerto 1900 no responde -- correcto','BAJO')

    # Seccion 10: Recomendaciones
    pdf.section_title('10. RECOMENDACIONES')
    for sug in suggests:
        pdf.data_row('[Accion]', sug, 'MEDIO')
    if not suggests:
        pdf.data_row('ESTADO','Mantener firmware actualizado','INFO')

    # Seccion 11: Graficas — una por pagina, centradas verticalmente
    charts = generate_charts(results, target)
    if charts:
        for idx, (title_c, path) in enumerate(charts):
            if not os.path.exists(path):
                continue
            pdf.add_page()
            # Header ocupa ~28mm, section_title ~12mm → contenido desde y≈42
            pdf.section_title(f'11. ANALISIS GRAFICO — {_s(title_c.upper())}')

            # Área disponible: desde get_y()+2 hasta 276mm (antes del footer)
            content_top = pdf.get_y() + 4
            available_h = 276 - content_top   # ~230mm disponibles

            try:
                if 'radar' in path.lower() or 'PERFIL' in title_c.upper():
                    # Radar cuadrado 7x7 pulgadas → proporcional
                    # Limitar a que quepa en el área disponible
                    img_w = min(160, available_h)
                    img_h = img_w   # cuadrado
                    img_x = (210 - img_w) / 2
                    # Centrar verticalmente en el espacio disponible
                    img_y = content_top + (available_h - img_h) / 2
                    pdf.image(path, x=img_x, y=img_y, w=img_w)
                else:
                    # Barras landscape 10x4.5 → ratio 2.22
                    img_w = 182
                    img_h = img_w / 2.22   # ≈82mm
                    img_x = 14
                    # Centrar verticalmente
                    img_y = content_top + (available_h - img_h) / 2
                    pdf.image(path, x=img_x, y=img_y, w=img_w)
            except Exception as e:
                pdf.set_y(content_top)
                pdf.data_row('Grafica', f'No disponible: {_s(str(e)[:50])}', 'INFO')

        for _, path in charts:
            try: os.unlink(path)
            except: pass

    # Pie
    pdf.ln(3)
    pdf.set_font('Courier','I',7); pdf.set_text_color(80,90,110)
    pdf.multi_cell(0,4,_s(
        'Reporte generado por CRYPT3CHO RouterGuard v1.1. '
        'Solo para uso en redes propias o con autorizacion del cliente. '
        'CRYPT3CHO // crypt3cho.com'))

    pdf.output(filename)
    return True

# ─────────────────────────────────────────────────────────────────────────────
# 1. INFORMACIÓN BÁSICA DE RED
# ─────────────────────────────────────────────────────────────────────────────
def check_network_info():
    section("1. INFORMACIÓN DE RED LOCAL")
    data = {}

    # IP local y gateway
    out, _ = run("ip route show default")
    print(f"  Gateway por defecto:  {c('info', out)}")
    data["default_route"] = out

    out, _ = run("ip addr show | grep 'inet ' | grep -v '127.0.0.1'")
    print(f"  IPs locales:\n{c('info', out)}")
    data["local_ips"] = out

    # MAC del router (ARP)
    run(f"ping -c 1 -W 1 {TARGET} > /dev/null 2>&1")
    out, _ = run(f"arp -n {TARGET}")
    print(f"  ARP del router:  {c('info', out)}")
    data["router_arp"] = out

    # DNS activos
    out, _ = run("cat /etc/resolv.conf | grep nameserver")
    print(f"  DNS configurados:\n{c('info', out)}")
    data["dns"] = out

    # Interfaces WiFi
    out, _ = run("iw dev 2>/dev/null || iwconfig 2>/dev/null | grep -v 'no wireless'")
    if out and "TIMEOUT" not in out:
        print(f"  Interfaces WiFi:\n{c('info', out)}")
    data["wifi_ifaces"] = out

    results["network_info"] = data

# ─────────────────────────────────────────────────────────────────────────────
# 2. DIAGNÓSTICO DE VELOCIDAD Y LATENCIA
# ─────────────────────────────────────────────────────────────────────────────
def ping_stats(host, count=10):
    """Devuelve dict con min/avg/max/loss de ping."""
    out, code = run(f"ping -c {count} -i 0.2 -W 2 {host}")
    stats = {"host": host, "raw": out, "reachable": code == 0}
    if code == 0:
        # Extraer min/avg/max/mdev
        m = re.search(r"(\d+\.?\d*)/(\d+\.?\d*)/(\d+\.?\d*)/(\d+\.?\d*)", out)
        if m:
            stats.update({
                "min_ms": float(m.group(1)),
                "avg_ms": float(m.group(2)),
                "max_ms": float(m.group(3)),
                "jitter_ms": float(m.group(4)),
            })
        # Packet loss
        loss = re.search(r"(\d+)% packet loss", out)
        if loss:
            stats["packet_loss_pct"] = int(loss.group(1))
    return stats

def interpret_latency(avg_ms, destination="router"):
    if avg_ms < 2:
        return c("ok", f"Excelente ({avg_ms:.1f}ms) — conexión limpia al {destination}")
    elif avg_ms < 10:
        return c("ok", f"Buena ({avg_ms:.1f}ms) — normal para {destination} local")
    elif avg_ms < 30:
        return c("warn", f"Aceptable ({avg_ms:.1f}ms) — posible carga en {destination}")
    else:
        return c("bad", f"Alta ({avg_ms:.1f}ms) — {destination} bajo estrés o problema físico")

def check_latency():
    section("2. LATENCIA Y CALIDAD DE SEÑAL")
    data = {}

    # Router local
    print(f"\n  → Ping al router ({TARGET})...")
    stats = ping_stats(TARGET, count=20)
    data["router"] = stats
    if stats["reachable"] and "avg_ms" in stats:
        print(f"    {interpret_latency(stats['avg_ms'], 'router')}")
        print(f"    Min: {stats['min_ms']}ms  Max: {stats['max_ms']}ms  "
              f"Jitter: {stats['jitter_ms']}ms  Loss: {stats.get('packet_loss_pct',0)}%")
    else:
        print(c("bad", "    Router no responde a ping"))

    # IPs externas en paralelo
    print(f"\n  → Ping a IPs externas (detecta si el problema es el router o la fibra)...")
    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = {ex.submit(ping_stats, ip, 10): ip for ip in EXTERNAL_IPS}
        for future in as_completed(futures):
            ip = futures[future]
            s = future.result()
            data[f"external_{ip}"] = s
            if s["reachable"] and "avg_ms" in s:
                label = "Google DNS" if ip=="8.8.8.8" else "Cloudflare" if ip=="1.1.1.1" else "OpenDNS"
                print(f"    {label} ({ip}):  {interpret_latency(s['avg_ms'], 'ISP/Internet')}")
            else:
                print(c("bad", f"    {ip}: no alcanzable"))

    # Traceroute al primer salto externo
    print(f"\n  → Traceroute (primeros 5 saltos)...")
    out, _ = run("traceroute -m 5 -w 2 8.8.8.8", timeout=20)
    print(f"    {c('info', out)}")
    data["traceroute"] = out

    results["latency"] = data

    # DIAGNÓSTICO: separar problema de router vs ISP
    if data["router"].get("avg_ms", 999) > 15:
        print(c("warn", "\n  ⚠  Alta latencia AL ROUTER → problema de LAN/WiFi o CPU del router saturada"))
    elif any(data.get(f"external_{ip}",{}).get("avg_ms",999) > 50 for ip in EXTERNAL_IPS):
        print(c("warn", "\n  ⚠  Latencia al router OK pero alta al exterior → posible problema de fibra/ISP"))
    else:
        print(c("ok", "\n  ✓  Latencia normal tanto local como externa"))

# ─────────────────────────────────────────────────────────────────────────────
# 3. ESCANEO DE PUERTOS DEL ROUTER (nmap)
# ─────────────────────────────────────────────────────────────────────────────
def check_open_ports():
    section("3. PUERTOS ABIERTOS EN EL ROUTER (nmap)")
    data = {}

    # Verificar nmap disponible
    out, code = run("which nmap")
    if code != 0:
        print(c("bad", "  nmap no encontrado — instala con: sudo apt install nmap"))
        return

    print("  → Escaneo rápido de puertos comunes...")
    out, _ = run(f"nmap -sV --open -T4 -p 21,22,23,25,53,80,443,8080,8443,1900,5000 {TARGET}", timeout=60)
    print(f"\n{c('info', out)}")
    data["nmap_common"] = out

    # Detectar puertos peligrosos
    dangerous = {
        "21": "FTP (texto plano)",
        "23": "Telnet (texto plano — CRÍTICO)",
        "1900": "UPnP — vector de ataque conocido",
    }
    warnings = []
    for port, desc in dangerous.items():
        if f"{port}/tcp" in out and "open" in out:
            warnings.append((port, desc))

    if warnings:
        print(c("bad", "\n  ⚠  PUERTOS PELIGROSOS DETECTADOS:"))
        for port, desc in warnings:
            print(c("bad", f"     Puerto {port}: {desc}"))
    else:
        print(c("ok", "\n  ✓  No se detectaron puertos peligrosos abiertos"))

    # Script de detección de vulnerabilidades nmap
    print("\n  → Scripts NSE básicos (vulners/auth)...")
    out2, _ = run(f"nmap --script=auth,default -p 80,443,23,22 {TARGET}", timeout=90)
    print(f"\n{c('info', out2)}")
    data["nmap_scripts"] = out2

    results["ports"] = data

# ─────────────────────────────────────────────────────────────────────────────
# 4. DISPOSITIVOS EN LA RED (quién está conectado)
# ─────────────────────────────────────────────────────────────────────────────
def check_devices():
    section("4. DISPOSITIVOS EN LA RED LOCAL")
    data = {}

    # Obtener la subred
    out, _ = run("ip route | grep -v default | head -1")
    subnet = out.split()[0] if out else "192.168.0.0/24"
    print(f"  Subred detectada: {c('info', subnet)}")

    print("  → Escaneo ARP (rápido, sin ping)...")
    out, _ = run(f"nmap -sn -PR {subnet}", timeout=60)
    print(f"\n{c('info', out)}")
    data["arp_scan"] = out

    # Contar hosts
    hosts = re.findall(r"Nmap scan report for (.+)", out)
    print(f"\n  Hosts encontrados: {c('bold', str(len(hosts)))}")
    for h in hosts:
        print(f"    • {h}")
    data["hosts"] = hosts

    # Alternativamente con arp-scan si está instalado
    out2, code = run(f"arp-scan --localnet 2>/dev/null | head -30")
    if code == 0 and "Interface" in out2:
        print(f"\n  arp-scan:\n{c('info', out2)}")
        data["arp_scan_detail"] = out2

    results["devices"] = data

# ─────────────────────────────────────────────────────────────────────────────
# 5. AUDITORÍA DE SEGURIDAD WiFi (si hay interfaz inalámbrica)
# ─────────────────────────────────────────────────────────────────────────────
def check_wifi_security():
    section("5. SEGURIDAD WiFi")
    data = {}

    # Detectar interfaz WiFi
    out, code = run("iw dev | grep Interface | awk '{print $2}'")
    if code != 0 or not out:
        print(c("warn", "  No se detectó interfaz WiFi activa"))
        return

    iface = out.split("\n")[0].strip()
    print(f"  Interfaz WiFi: {c('info', iface)}")

    # Escanear redes cercanas
    print("  → Escaneando redes WiFi cercanas...")
    out, _ = run(f"iw dev {iface} scan 2>/dev/null | grep -E 'SSID|signal|RSN|WPA|freq'", timeout=15)
    if out:
        print(f"\n{c('info', out)}")
        data["wifi_scan"] = out

        # Detectar redes abiertas (sin RSN/WPA)
        ssids = re.findall(r"SSID: (.+)", out)
        print(f"\n  Redes detectadas: {len(ssids)}")

    # Canal y potencia de señal propia
    out2, _ = run(f"iw dev {iface} link 2>/dev/null")
    if out2:
        print(f"\n  Estado de conexión actual:\n{c('info', out2)}")
        data["link_info"] = out2

    # Calidad de señal con iwconfig
    out3, _ = run(f"iwconfig {iface} 2>/dev/null")
    if out3:
        signal = re.search(r"Signal level=(-\d+)", out3)
        quality = re.search(r"Link Quality=(\d+)/(\d+)", out3)
        if signal:
            dbm = int(signal.group(1))
            print(f"\n  Nivel de señal: {c('info', f'{dbm} dBm')}", end="")
            if dbm > -60:
                print(c("ok", " (Excelente)"))
            elif dbm > -70:
                print(c("ok", " (Buena)"))
            elif dbm > -80:
                print(c("warn", " (Débil — puede causar lentitud)"))
            else:
                print(c("bad", " (Muy débil — problema serio)"))
        data["signal_dbm"] = signal.group(1) if signal else "N/A"

    results["wifi"] = data

# ─────────────────────────────────────────────────────────────────────────────
# 6. TEST DE RENDIMIENTO DNS
# ─────────────────────────────────────────────────────────────────────────────
def check_dns():
    section("6. RENDIMIENTO DNS")
    data = {}
    domains = ["google.com", "cloudflare.com", "github.com"]

    # DNS del router vs DNS externo
    dns_servers = {
        "Router (local)": TARGET,
        "Google 8.8.8.8": "8.8.8.8",
        "Cloudflare 1.1.1.1": "1.1.1.1",
    }

    for dns_name, dns_ip in dns_servers.items():
        times = []
        for domain in domains:
            start = time.time()
            out, code = run(f"dig @{dns_ip} {domain} +time=3 +tries=1 +short", timeout=5)
            elapsed = (time.time() - start) * 1000
            if code == 0 and out:
                times.append(elapsed)
        if times:
            avg = sum(times) / len(times)
            rating = c("ok","Rápido") if avg<50 else c("warn","Lento") if avg<200 else c("bad","Muy lento")
            print(f"  {dns_name:<25} avg: {avg:>6.1f}ms  {rating}")
            data[dns_name] = {"avg_ms": round(avg, 1)}
        else:
            print(f"  {dns_name:<25} {c('bad','Sin respuesta')}")

    results["dns"] = data

# ─────────────────────────────────────────────────────────────────────────────
# 7. PANEL WEB DEL ROUTER (HTTP/HTTPS)
# ─────────────────────────────────────────────────────────────────────────────
def check_web_panel():
    section("7. PANEL WEB DEL ROUTER")
    data = {}

    for scheme in ["http", "https"]:
        url = f"{scheme}://{TARGET}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            ctx = None
            if scheme == "https":
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            resp = urllib.request.urlopen(req, timeout=5, context=ctx)
            headers = dict(resp.headers)
            data[scheme] = {
                "status": resp.status,
                "server": headers.get("Server","N/A"),
                "x_frame": headers.get("X-Frame-Options","AUSENTE ⚠"),
                "x_content": headers.get("X-Content-Type-Options","AUSENTE ⚠"),
            }
            print(f"  {scheme.upper()}: {c('ok','Accesible')}  "
                  f"Status: {resp.status}  "
                  f"Server: {c('info', headers.get('Server','N/A'))}")
            print(f"    X-Frame-Options: {data[scheme]['x_frame']}")
            print(f"    X-Content-Type:  {data[scheme]['x_content']}")
        except urllib.error.HTTPError as e:
            print(f"  {scheme.upper()}: {c('warn', f'HTTP {e.code}')}")
            data[scheme] = {"status": e.code}
        except Exception as e:
            print(f"  {scheme.upper()}: {c('bad', f'No accesible ({e.__class__.__name__})')}")
            data[scheme] = {"error": str(e)}

    # Intentar detectar firmware/modelo por respuesta HTTP
    out, _ = run(f"curl -sk --max-time 5 http://{TARGET}/ | grep -iE 'model|version|firmware|router' | head -5")
    if out:
        print(f"\n  Info detectada en HTML:\n{c('info', out)}")
        data["html_info"] = out

    results["web_panel"] = data

# ─────────────────────────────────────────────────────────────────────────────
# 8. VERIFICAR CREDENCIALES POR DEFECTO (HTTP Basic / Form)
# ─────────────────────────────────────────────────────────────────────────────
def check_default_creds():
    section("8. VERIFICACIÓN DE CREDENCIALES POR DEFECTO")
    print(c("warn", "  (Solo para tu propio router — uso educativo)"))
    data = {"default_cred_found": None}

    import base64

    # ── Paso 1: Obtener baseline sin credenciales ─────────────
    ref_out, _ = run(f"curl -sk --max-time 5 http://{TARGET}/")
    ref_len     = len(ref_out)
    ref_lower   = ref_out.lower()

    # Detectar si el router ya es accesible SIN autenticación
    admin_keywords = ['restart', 'reboot', 'util_restart', 'logout',
                      'sign out', 'admin panel', 'dashboard',
                      'wireless', 'wan setup', 'firewall']
    login_keywords = ['login', 'password', 'passwd', 'sign in',
                      'username', 'user name', 'contrasena', 'ingresa',
                      'enter password']

    ref_is_admin   = sum(1 for kw in admin_keywords if kw in ref_lower) >= 2
    ref_has_login  = any(kw in ref_lower for kw in login_keywords)

    if ref_is_admin and not ref_has_login:
        print(c("bad", "  ⚠  PANEL ACCESIBLE SIN AUTENTICACION"))
        print(c("bad", "      El router responde con contenido de administracion "
                        "sin requerir credenciales"))
        data["panel_open"] = True
        data["default_cred_found"] = {
            "user": "(ninguna)", "pass": "(ninguna)",
            "method": "no_auth_required", "confirmed": True,
        }
        results["credentials"] = data
        return

    # ── Paso 2: Detectar tipo de auth ─────────────────────────
    status_noauth, _ = run(
        f"curl -sk --max-time 4 -o /dev/null -w '%{{http_code}}' "
        f"http://{TARGET}/"
    )
    uses_basic_auth = (status_noauth == "401")

    default_creds = [
        ("admin", "admin"), ("admin", "password"), ("admin", ""),
        ("admin", "1234"),  ("root",  "root"),      ("user", "user"),
    ]

    found = False
    for user, passwd in default_creds:
        token = base64.b64encode(f"{user}:{passwd}".encode()).decode()
        auth_out, _ = run(
            f"curl -sk --max-time 5 "
            f"-H 'Authorization: Basic {token}' http://{TARGET}/"
        )
        auth_len   = len(auth_out)
        auth_lower = auth_out.lower()

        if uses_basic_auth:
            # Basic Auth: si antes era 401 y ahora 200 → válida
            status_with, _ = run(
                f"curl -sk --max-time 4 -o /dev/null -w '%{{http_code}}' "
                f"-H 'Authorization: Basic {token}' http://{TARGET}/"
            )
            if status_with in ("200", "302"):
                print(c("bad", f"  ⚠  Credencial Basic Auth confirmada: "
                               f"{user}:{passwd or '(vacia)'}"))
                data["default_cred_found"] = {
                    "user": user, "pass": passwd,
                    "method": "basic_auth_401_to_200", "confirmed": True,
                }
                found = True
                break
            else:
                print(c("info", f"  → {user}:{passwd or '(vacia)'} — rechazada ({status_with})"))
        else:
            # Form-based: el contenido DEBE cambiar de forma significativa
            # Criterios estrictos para evitar falsos positivos:
            # 1. Tamaño cambia >30%
            # 2. Formulario de login desaparece
            # 3. Aparecen keywords de admin que NO estaban en la referencia
            size_change = abs(auth_len - ref_len) / max(ref_len, 1)
            login_gone  = ref_has_login and not any(
                kw in auth_lower for kw in login_keywords)
            new_admin   = any(kw in auth_lower and kw not in ref_lower
                              for kw in admin_keywords)

            if size_change > 0.30 and (login_gone or new_admin):
                print(c("bad", f"  ⚠  Credencial posiblemente valida: "
                               f"{user}:{passwd or '(vacia)'} "
                               f"(cambio de contenido {ref_len}->{auth_len})"))
                data["default_cred_found"] = {
                    "user": user, "pass": passwd,
                    "method": "content_diff", "confirmed": True,
                }
                found = True
                break
            else:
                print(c("info", f"  → {user}:{passwd or '(vacia)'} — "
                                f"contenido sin cambio significativo "
                                f"({ref_len} vs {auth_len} bytes, "
                                f"delta {size_change:.0%}) — descartado"))

    if not found:
        print(c("ok", "  ✓  Sin credenciales por defecto verificadas"))
        print(c("ok",
            "    Nota: este router sirve HTTP 200 sin auth -- "
            "para verificar manualmente:\n"
            f"    curl -sk -u admin:TU_PASS http://{TARGET}/ | grep logout"))
    results["credentials"] = data

# ─────────────────────────────────────────────────────────────────────────────
# 9. VERIFICAR UPnP (vector de ataque)
# ─────────────────────────────────────────────────────────────────────────────
def check_upnp():
    section("9. UPnP — UNIVERSAL PLUG AND PLAY")
    data = {}

    out, _ = run(f"curl -sk --max-time 5 http://{TARGET}:1900/ 2>&1")
    if out and "TIMEOUT" not in out:
        print(c("warn", f"  ⚠  UPnP posiblemente activo en puerto 1900"))
        data["upnp_1900"] = "open"
    else:
        print(c("ok", f"  ✓  Puerto UPnP 1900 no responde"))
        data["upnp_1900"] = "closed"

    # upnp vía nmap
    out2, _ = run(f"nmap -sU -p 1900 --script upnp-info {TARGET}", timeout=30)
    print(f"\n{c('info', out2)}")
    data["nmap_upnp"] = out2

    results["upnp"] = data

# ─────────────────────────────────────────────────────────────────────────────
# 10. RESUMEN Y RECOMENDACIONES
# ─────────────────────────────────────────────────────────────────────────────
def print_summary():
    section("RESUMEN EJECUTIVO")

    issues = []
    suggestions = []

    # Latencia
    router_avg = results.get("latency",{}).get("router",{}).get("avg_ms", 0)
    if router_avg > 15:
        issues.append(f"Alta latencia al router: {router_avg:.1f}ms")
        suggestions.append("Conectarse por cable Ethernet para descartar WiFi como causa")

    # Puertos peligrosos
    ports_out = results.get("ports",{}).get("nmap_common","")
    if "23/tcp" in ports_out and "open" in ports_out:
        issues.append("Telnet (puerto 23) está ABIERTO — crítico")
        suggestions.append("Deshabilitar Telnet en el panel del router inmediatamente")

    if "21/tcp" in ports_out and "open" in ports_out:
        issues.append("FTP (puerto 21) abierto — inseguro")
        suggestions.append("Deshabilitar FTP si no lo usas")

    # UPnP
    if results.get("upnp",{}).get("upnp_1900") == "open":
        issues.append("UPnP activo — vector de ataque")
        suggestions.append("Desactivar UPnP en configuración del router")

    # Credenciales
    cred = results.get("credentials",{}).get("default_cred_found")
    if cred:
        issues.append(f"Credencial por defecto activa: {cred['user']}:{cred['pass']}")
        suggestions.append("Cambiar contraseña del router INMEDIATAMENTE")

    # WiFi signal
    signal = results.get("wifi",{}).get("signal_dbm","")
    try:
        signal_ok = signal and signal != "N/A" and int(signal) < -75
    except (ValueError, TypeError):
        signal_ok = False
    if signal_ok:
        issues.append(f"Señal WiFi débil: {signal} dBm")
        suggestions.append("Reubicar el router o usar cable Ethernet")

    if issues:
        print(c("bad", "  PROBLEMAS DETECTADOS:"))
        for i, issue in enumerate(issues, 1):
            print(c("bad", f"    {i}. {issue}"))
        print(c("warn", "\n  RECOMENDACIONES:"))
        for i, s in enumerate(suggestions, 1):
            print(c("warn", f"    {i}. {s}"))
    else:
        print(c("ok", "  ✓  No se detectaron problemas críticos"))

    results["timestamp"] = datetime.now().isoformat()
    results["target"] = TARGET
    results["summary"] = {"issues": issues, "suggestions": suggestions}

    # Generar PDF CRYPT3CHO
    print(c("info", "\n  Generando reporte PDF..."))
    if generate_pdf(results, REPORT_FILE):
        print(c("ok", f"  Reporte: {REPORT_FILE}"))
    else:
        # fallback JSON si fpdf2 no disponible
        json_file = REPORT_FILE.replace('.pdf', '.json')
        with open(json_file, "w") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(c("info", f"  JSON fallback: {json_file}"))

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    global TARGET
    parser = argparse.ArgumentParser(description="Auditoría de router para laboratorio")
    parser.add_argument("--target", default=TARGET, help="IP del router (default: 192.168.0.1)")
    parser.add_argument("--mode", choices=["full","speed","security"], default="full",
                        help="full=todo, speed=solo latencia/DNS, security=puertos/credenciales")
    args = parser.parse_args()

    TARGET = args.target

    print(c("bold", f"\n{'='*60}"))
    print(c("bold", f"  ROUTER AUDIT — {TARGET}"))
    print(c("bold", f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print(c("bold", f"{'='*60}"))
    print(c("warn", "\n  ADVERTENCIA: Solo usar en redes propias o con permiso explícito\n"))

    if args.mode in ("full", "speed"):
        check_network_info()
        check_latency()
        check_dns()
    if args.mode in ("full", "security"):
        check_open_ports()
        check_devices()
        check_wifi_security()
        check_web_panel()
        check_default_creds()
        check_upnp()
    if args.mode == "full":
        pass  # ya ejecutó todo

    print_summary()

if __name__ == "__main__":
    main()
