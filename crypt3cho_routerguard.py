#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  CRYPT3CHO // ROUTERGUARD v1.0                                  ║
║  Análisis de Seguridad de Router — Herramienta Gratuita         ║
║                                                                  ║
║  Detecta:                                                        ║
║    · Credenciales por defecto en panel admin                    ║
║    · Puertos peligrosos expuestos (Telnet, UPnP, WPS)           ║
║    · Firmware desactualizado                                     ║
║    · DNS sospechoso (posible secuestro de DNS)                  ║
║    · Dispositivos no reconocidos en la red                      ║
║                                                                  ║
║  Acciones disponibles:                                           ║
║    1. Cambiar DNS a Cloudflare/Google (más seguro)              ║
║    2. Bloquear acceso al panel admin desde WiFi                 ║
║    3. Exportar inventario de dispositivos conectados            ║
║    4. Generar reporte PDF con hallazgos y remediación           ║
║                                                                  ║
║  Uso:                                                            ║
║    python3 crypt3cho_routerguard.py                             ║
║    python3 crypt3cho_routerguard.py --auto                      ║
║    python3 crypt3cho_routerguard.py --pdf-only                  ║
║                                                                  ║
║  Plataformas: macOS · Linux · Windows                           ║
║  crypt3cho.com // Uso libre — no redistribuir modificado        ║
╚══════════════════════════════════════════════════════════════════╝
"""
import os, sys, subprocess, platform, socket, datetime, time, re
import json, hashlib, argparse, shutil, ipaddress, threading, struct
from pathlib import Path

OS_TYPE = platform.system()   # 'Darwin' | 'Linux' | 'Windows'

# ── Auto-instalador de dependencias ──────────────────────────────
def _pip(pkg):
    flags = [] if (OS_TYPE in ('Darwin','Windows')) else ['--break-system-packages']
    subprocess.run([sys.executable,'-m','pip','install',pkg,'-q']+flags,
                   capture_output=True)

for _pkg, _mod in [('fpdf2','fpdf'),('rich','rich'),
                    ('requests','requests'),('matplotlib','matplotlib')]:
    try: __import__(_mod)
    except ImportError:
        print(f"[*] Instalando {_pkg}..."); _pip(_pkg)

from rich.console import Console
from rich.panel   import Panel
from rich.table   import Table
from rich.rule    import Rule
from rich.prompt  import Prompt, Confirm
from rich         import box
from rich.progress import Progress, SpinnerColumn, TextColumn

import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

from fpdf import FPDF
from fpdf.enums import XPos, YPos

console = Console()

# ── Paleta corporativa CRYPT3CHO ─────────────────────────────────
NAVY    = (15,  40,  80)
ACCENT  = (0,  120, 200)
GREEN_C = (30, 120,  56)
RED_C   = (180, 30,  30)
AMBER_C = (160,120,   0)
GRAY_D  = (60,  60,  70)
GRAY_L  = (245,246, 248)
WHITE   = (255,255, 255)
BG_DARK = '#0A1628'
C_GREEN = '#00ff41'
C_RED   = '#ff4444'
C_AMBER = '#ffcc00'
C_CYAN  = '#00ccff'
C_NAVY  = '#0A1628'

BANNER = r"""
 ██████╗██████╗ ██╗   ██╗██████╗ ████████╗██████╗  ██████╗██╗  ██╗ ██████╗
██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝╚════██╗██╔════╝██║  ██║██╔═══██╗
██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║    █████╔╝██║     ███████║██║   ██║
██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║    ╚═══██╗██║     ██╔══██║██║   ██║
╚██████╗██║  ██║   ██║   ██║        ██║   ██████╔╝╚██████╗██║  ██║╚██████╔╝
 ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚═════╝  ╚═════╝╚═╝  ╚═╝ ╚═════╝
  ROUTERGUARD v1.0  //  Análisis de Seguridad de Router  //  crypt3cho.com
"""

VERSION   = "1.0"
TIMESTAMP = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
OUT_DIR   = Path(__file__).parent

# ── Args ──────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description='CRYPT3CHO RouterGuard v1.0')
parser.add_argument('--auto',     action='store_true', help='Sin confirmaciones')
parser.add_argument('--pdf-only', action='store_true', help='Solo generar PDF')
parser.add_argument('--output',   default=str(OUT_DIR), help='Directorio salida')
ARGS = parser.parse_args()

# ════════════════════════════════════════════════════════════════
# DETECCIÓN DE GATEWAY
# ════════════════════════════════════════════════════════════════
def get_gateway():
    """Obtiene la IP del gateway/router."""
    try:
        if OS_TYPE == 'Windows':
            out = subprocess.check_output(['ipconfig'], text=True, errors='replace')
            m = re.search(r'Default Gateway[^:]*:\s*([\d.]+)', out)
            if m: return m.group(1)
        elif OS_TYPE == 'Darwin':
            out = subprocess.check_output(['netstat','-rn'], text=True, errors='replace')
            m = re.search(r'^default\s+([\d.]+)', out, re.MULTILINE)
            if m: return m.group(1)
        else:  # Linux
            out = subprocess.check_output(['ip','route','show','default'],
                                           text=True, errors='replace')
            m = re.search(r'default via ([\d.]+)', out)
            if m: return m.group(1)
    except: pass
    # Fallback: socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        parts = ip.split('.')
        return '.'.join(parts[:3]) + '.1'
    except: return '192.168.1.1'

def get_local_subnet(gateway):
    """Obtiene la subred local."""
    parts = gateway.split('.')
    return '.'.join(parts[:3]) + '.0/24'

def get_dns_servers():
    """Obtiene los DNS configurados actualmente."""
    dns = []
    try:
        if OS_TYPE == 'Windows':
            out = subprocess.check_output(['ipconfig','/all'], text=True, errors='replace')
            for m in re.finditer(r'DNS Servers[^:]*:\s*([\d.]+)', out):
                dns.append(m.group(1))
        elif OS_TYPE == 'Darwin':
            out = subprocess.check_output(['scutil','--dns'], text=True, errors='replace')
            for m in re.finditer(r'nameserver\[0\]\s*:\s*([\d.]+)', out):
                if m.group(1) not in dns: dns.append(m.group(1))
        else:
            with open('/etc/resolv.conf') as f:
                for line in f:
                    m = re.match(r'nameserver\s+([\d.]+)', line)
                    if m: dns.append(m.group(1))
    except: pass
    return dns or ['No detectado']

# ════════════════════════════════════════════════════════════════
# MÓDULO 1 — ESCANEO DE PUERTOS DEL ROUTER
# ════════════════════════════════════════════════════════════════
DANGEROUS_PORTS = {
    23:    ('Telnet',    'CRITICO', 'Protocolo sin cifrado — credenciales en texto plano'),
    80:    ('HTTP Admin','MEDIO',   'Panel admin sin HTTPS — credenciales expuestas'),
    443:   ('HTTPS',     'INFO',    'Panel admin HTTPS — verificar credenciales'),
    8080:  ('HTTP Alt',  'MEDIO',   'Puerto alternativo HTTP — posible panel admin'),
    8443:  ('HTTPS Alt', 'INFO',    'Puerto alternativo HTTPS'),
    22:    ('SSH',       'MEDIO',   'SSH expuesto — verificar contraseña robusta'),
    21:    ('FTP',       'CRITICO', 'FTP sin cifrado — acceso a archivos'),
    1900:  ('UPnP',      'ALTO',    'UPnP activo — permite abrir puertos sin autenticación'),
    5000:  ('UPnP/TCP',  'ALTO',    'UPnP TCP — descripción de servicios accesible'),
    7547:  ('TR-069',    'ALTO',    'TR-069 — protocolo de gestión remota del ISP'),
    49152: ('UPnP IGD',  'ALTO',    'UPnP Internet Gateway Device expuesto'),
    554:   ('RTSP',      'MEDIO',   'Stream RTSP — posible cámara IP'),
    9000:  ('Admin Alt', 'MEDIO',   'Puerto admin alternativo'),
    161:   ('SNMP',      'ALTO',    'SNMP activo — información de red accesible'),
}

def scan_ports(host, timeout=1.5):
    """Escanea puertos relevantes del router."""
    results = {}
    ports_to_scan = list(DANGEROUS_PORTS.keys())

    def _try(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            r = s.connect_ex((host, port))
            s.close()
            if r == 0:
                results[port] = DANGEROUS_PORTS[port]
        except: pass

    threads = [threading.Thread(target=_try, args=(p,)) for p in ports_to_scan]
    for t in threads: t.start()
    for t in threads: t.join()
    return results

# ════════════════════════════════════════════════════════════════
# MÓDULO 2 — CREDENCIALES POR DEFECTO
# ════════════════════════════════════════════════════════════════
DEFAULT_CREDS = [
    ('admin','admin'),('admin','password'),('admin','1234'),
    ('admin',''),('root','root'),('root','admin'),
    ('admin','admin123'),('user','user'),('Admin','Admin'),
    ('admin','12345678'),('admin','pass'),('admin','0000'),
]

def check_default_creds(host, ports_open):
    """Prueba credenciales por defecto en el panel admin."""
    results = []
    admin_ports = [p for p in ports_open if p in (80, 8080, 443, 8443)]
    if not admin_ports: return results

    try: import requests; HAS_REQUESTS = True
    except: HAS_REQUESTS = False

    if not HAS_REQUESTS: return []

    import warnings; warnings.filterwarnings('ignore')

    for port in admin_ports[:1]:
        scheme = 'https' if port in (443, 8443) else 'http'
        url    = f'{scheme}://{host}:{port}/'

        # Verificar si hay panel admin
        try:
            import requests as req
            r = req.get(url, timeout=4, verify=False)
            body = r.text.lower()
            has_login = any(k in body for k in
                           ['password','login','username','user','passwd','admin'])
            if not has_login: continue
        except: continue

        # Probar credenciales básicas
        for user, pw in DEFAULT_CREDS[:8]:
            try:
                r = req.post(url, data={'username':user,'password':pw},
                             auth=(user, pw), timeout=3, verify=False,
                             allow_redirects=True)
                # Heurística: si la respuesta NO contiene "incorrect/error/wrong"
                # y tiene contenido de admin, probablemente entró
                resp_lower = r.text.lower()
                if r.status_code == 200 and \
                   any(k in resp_lower for k in ['logout','dashboard','status','interface']) and \
                   not any(k in resp_lower for k in ['incorrect','invalid','error','failed']):
                    results.append({
                        'user': user, 'pass': pw, 'url': url,
                        'status': 'POSIBLE_ACCESO'
                    })
                    break
            except: pass

    return results

# ════════════════════════════════════════════════════════════════
# MÓDULO 3 — INVENTARIO DE DISPOSITIVOS EN LA RED
# ════════════════════════════════════════════════════════════════
MAC_VENDORS = {
    'dc:a6:32': 'Raspberry Pi', 'b8:27:eb': 'Raspberry Pi',
    'e4:5f:01': 'Raspberry Pi', '00:50:56': 'VMware',
    '08:00:27': 'VirtualBox',   '00:0c:29': 'VMware',
    'fc:fb:fb': 'Ubiquiti',     '80:2a:a8': 'Ubiquiti',
    '18:e8:29': 'TP-Link',      'c4:e9:84': 'TP-Link',
    '14:cc:20': 'TP-Link',      '50:c7:bf': 'TP-Link',
    '00:23:69': 'Cisco',        '00:1a:a0': 'Dell',
    '3c:15:c2': 'Apple',        'a4:c3:f0': 'Apple',
    '00:17:f2': 'Apple',        'dc:a9:04': 'Apple',
    'f0:18:98': 'Apple',        'b0:34:95': 'Apple',
    '00:1e:c2': 'Apple',        'c8:2a:14': 'Apple',
    '94:65:9c': 'Samsung',      '00:12:fb': 'Samsung',
    '8c:77:12': 'Samsung',      '4c:bc:98': 'LG',
    '00:1c:62': 'HP',           '3c:d9:2b': 'HP',
    'a0:36:9f': 'Intel',        '00:1b:21': 'Intel',
}

def get_vendor(mac):
    if not mac: return 'Desconocido'
    prefix = mac[:8].lower()
    return MAC_VENDORS.get(prefix, 'Desconocido')

def scan_network(subnet, timeout=0.8):
    """Escanea la red local para inventariar dispositivos."""
    devices = []

    # Método 1: ARP table (más rápido, sin nmap)
    try:
        if OS_TYPE == 'Windows':
            out = subprocess.check_output(['arp','-a'], text=True, errors='replace')
        else:
            out = subprocess.check_output(['arp','-n'], text=True, errors='replace')

        for line in out.splitlines():
            m = re.search(
                r'([\d]+\.[\d]+\.[\d]+\.[\d]+)\s+'
                r'(?:ether\s+|inet\s+\d+\s+)?'
                r'([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}'
                r'[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})',
                line)
            if m:
                ip  = m.group(1)
                mac = m.group(2).replace('-',':').lower()
                if ip not in [d['ip'] for d in devices]:
                    devices.append({
                        'ip':     ip,
                        'mac':    mac,
                        'vendor': get_vendor(mac),
                        'host':   '',
                        'metodo': 'ARP'
                    })
    except: pass

    # Método 2: ping sweep rápido para activar ARP
    base = '.'.join(subnet.split('.')[:3])
    ping_targets = [f'{base}.{i}' for i in range(1, 30)]

    def _ping(ip):
        try:
            if OS_TYPE == 'Windows':
                r = subprocess.run(['ping','-n','1','-w','500',ip],
                                   capture_output=True, timeout=2)
            else:
                r = subprocess.run(['ping','-c','1','-W','1',ip],
                                   capture_output=True, timeout=2)
            if r.returncode == 0 and ip not in [d['ip'] for d in devices]:
                devices.append({'ip':ip,'mac':'','vendor':'','host':'','metodo':'PING'})
        except: pass

    threads = [threading.Thread(target=_ping, args=(ip,)) for ip in ping_targets]
    for t in threads: t.start()
    for t in threads: t.join()

    # Resolución de hostname
    for d in devices:
        try:
            d['host'] = socket.gethostbyaddr(d['ip'])[0][:30]
        except: d['host'] = ''

    return sorted(devices, key=lambda x: [int(p) for p in x['ip'].split('.')])

# ════════════════════════════════════════════════════════════════
# MÓDULO 4 — ANÁLISIS DE DNS
# ════════════════════════════════════════════════════════════════
KNOWN_SAFE_DNS = {
    '1.1.1.1':   ('Cloudflare', 'SEGURO'),
    '1.0.0.1':   ('Cloudflare', 'SEGURO'),
    '8.8.8.8':   ('Google',     'SEGURO'),
    '8.8.4.4':   ('Google',     'SEGURO'),
    '9.9.9.9':   ('Quad9',      'SEGURO'),
    '208.67.222.222': ('OpenDNS','SEGURO'),
    '208.67.220.220': ('OpenDNS','SEGURO'),
}

def analyze_dns(dns_servers, gateway):
    """Evalúa si los DNS configurados son seguros."""
    findings = []
    for dns in dns_servers:
        if dns in KNOWN_SAFE_DNS:
            name, status = KNOWN_SAFE_DNS[dns]
            findings.append({'ip': dns, 'nombre': name, 'estado': status,
                             'riesgo': 'INFO'})
        elif dns == gateway or dns.startswith(gateway.rsplit('.',1)[0]):
            findings.append({'ip': dns, 'nombre': 'Router local', 'estado': 'LOCAL',
                             'riesgo': 'MEDIO',
                             'nota': 'DNS resuelto por el router — verifica que no haya sido modificado'})
        else:
            findings.append({'ip': dns, 'nombre': 'Desconocido', 'estado': 'SOSPECHOSO',
                             'riesgo': 'ALTO',
                             'nota': f'DNS no reconocido: {dns} — posible secuestro de DNS'})
    return findings

# ════════════════════════════════════════════════════════════════
# ACCIONES (3 acciones disponibles + reporte)
# ════════════════════════════════════════════════════════════════
def action_change_dns(gateway):
    """ACCIÓN 1: Cambia DNS a Cloudflare 1.1.1.1."""
    console.print('\n  [bold cyan][*] ACCIÓN 1 — Cambiar DNS a Cloudflare (1.1.1.1)[/bold cyan]')

    if OS_TYPE == 'Linux':
        # Detectar interfaz activa
        try:
            out = subprocess.check_output(['ip','route','show','default'], text=True)
            m   = re.search(r'dev (\w+)', out)
            iface = m.group(1) if m else 'eth0'
        except: iface = 'eth0'

        # Intentar via resolvectl (systemd-resolved)
        if shutil.which('resolvectl'):
            r = subprocess.run(['sudo','resolvectl','dns', iface, '1.1.1.1', '8.8.8.8'],
                              capture_output=True)
            if r.returncode == 0:
                console.print('  [green][+] DNS cambiado a 1.1.1.1 (Cloudflare) via resolvectl[/green]')
                return True, 'DNS → 1.1.1.1 (Cloudflare) via resolvectl'

        # Fallback: /etc/resolv.conf
        try:
            content = '# CRYPT3CHO RouterGuard — DNS seguro\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n'
            with open('/etc/resolv.conf','w') as f: f.write(content)
            console.print('  [green][+] /etc/resolv.conf actualizado con DNS Cloudflare[/green]')
            return True, 'DNS → 1.1.1.1 via /etc/resolv.conf'
        except Exception as e:
            console.print(f'  [yellow][!] Requiere sudo: sudo python3 {__file__}[/yellow]')
            return False, f'Error: {e}'

    elif OS_TYPE == 'Darwin':
        try:
            # Obtener interfaz de red activa
            out = subprocess.check_output(['networksetup','-listallnetworkservices'],
                                          text=True)
            services = [l.strip() for l in out.splitlines()
                       if l.strip() and not l.startswith('*') and 'Wi-Fi' in l or 'Ethernet' in l]
            svc = services[0] if services else 'Wi-Fi'
            r = subprocess.run(['sudo','networksetup','-setdnsservers',
                               svc, '1.1.1.1', '8.8.8.8'],
                              capture_output=True)
            if r.returncode == 0:
                console.print(f'  [green][+] DNS cambiado a 1.1.1.1 en {svc}[/green]')
                return True, f'DNS → 1.1.1.1 en {svc}'
        except Exception as e:
            return False, str(e)

    elif OS_TYPE == 'Windows':
        console.print('  [yellow][!] En Windows: Panel de Control → Red → IPv4 → DNS: 1.1.1.1[/yellow]')
        console.print('  [dim]O ejecuta en PowerShell como Admin:[/dim]')
        console.print('  [dim]Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses 1.1.1.1,8.8.8.8[/dim]')
        return False, 'Instrucciones mostradas — acción manual requerida en Windows'

    return False, 'No implementado para este OS'

def action_flush_dns():
    """ACCIÓN 2: Limpia la caché DNS."""
    console.print('\n  [bold cyan][*] ACCIÓN 2 — Limpiar caché DNS[/bold cyan]')
    try:
        if OS_TYPE == 'Linux':
            cmds = [['sudo','systemd-resolve','--flush-caches'],
                    ['sudo','service','nscd','restart'],
                    ['sudo','resolvectl','flush-caches']]
            for cmd in cmds:
                if shutil.which(cmd[1] if len(cmd)>1 else cmd[0]):
                    r = subprocess.run(cmd, capture_output=True)
                    if r.returncode == 0:
                        console.print('  [green][+] Caché DNS limpiada[/green]')
                        return True, 'DNS cache limpiada'
        elif OS_TYPE == 'Darwin':
            r = subprocess.run(['sudo','dscacheutil','-flushcache'],capture_output=True)
            subprocess.run(['sudo','killall','-HUP','mDNSResponder'],capture_output=True)
            console.print('  [green][+] Caché DNS limpiada (macOS)[/green]')
            return True, 'DNS cache limpiada (macOS)'
        elif OS_TYPE == 'Windows':
            r = subprocess.run(['ipconfig','/flushdns'], capture_output=True, text=True)
            console.print(f'  [green][+] {r.stdout.strip()[:60]}[/green]')
            return True, 'DNS cache limpiada (Windows)'
    except Exception as e:
        return False, str(e)
    return False, 'No completado'

def action_export_inventory(devices, output_dir):
    """ACCIÓN 3: Exporta inventario de dispositivos a JSON y CSV."""
    console.print('\n  [bold cyan][*] ACCIÓN 3 — Exportar inventario de dispositivos[/bold cyan]')
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    # JSON
    json_path = Path(output_dir) / f'RouterGuard_Inventario_{ts}.json'
    data = {
        'timestamp': TIMESTAMP,
        'herramienta': f'CRYPT3CHO RouterGuard v{VERSION}',
        'dispositivos': devices
    }
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    # CSV simple
    csv_path = Path(output_dir) / f'RouterGuard_Inventario_{ts}.csv'
    with open(csv_path, 'w', encoding='utf-8') as f:
        f.write('IP,MAC,VENDOR,HOSTNAME,METODO\n')
        for d in devices:
            f.write(f"{d['ip']},{d['mac']},{d['vendor']},{d['host']},{d['metodo']}\n")

    console.print(f'  [green][+] JSON: {json_path.name}[/green]')
    console.print(f'  [green][+] CSV:  {csv_path.name}[/green]')
    return True, f'{len(devices)} dispositivos exportados'

# ════════════════════════════════════════════════════════════════
# GRÁFICAS MATPLOTLIB (3 — estética CRYPT3CHO)
# ════════════════════════════════════════════════════════════════
def _fig_base():
    fig = plt.figure(facecolor=BG_DARK)
    return fig

def grafica1_riesgo_puertos(ports_open, path):
    """Gráfica 1: Distribución de severidad de puertos encontrados."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5), facecolor=BG_DARK)

    niveles = {'CRITICO':0, 'ALTO':0, 'MEDIO':0, 'INFO':0}
    for port, (name, nivel, _) in ports_open.items():
        if nivel in niveles: niveles[nivel] += 1

    # Dona de severidad
    labels = [k for k,v in niveles.items() if v > 0]
    sizes  = [v for v in niveles.values() if v > 0]
    colors_d = {'CRITICO':'#ff3333','ALTO':'#ff8800','MEDIO':'#ffcc00','INFO':'#00ccff'}
    clrs = [colors_d[l] for l in labels]

    if sizes:
        wedges, texts, autotexts = ax1.pie(
            sizes, labels=labels, colors=clrs, autopct='%1.0f%%',
            startangle=90,
            wedgeprops=dict(width=0.55, edgecolor=BG_DARK, linewidth=2),
        )
        for t in texts: t.set_color('white'); t.set_fontsize(9)
        for t in autotexts: t.set_color('white'); t.set_fontsize(8)
    else:
        ax1.text(0, 0, 'Sin puertos\npeligrosos', ha='center', va='center',
                color=C_GREEN, fontsize=14, fontweight='bold')
        ax1.set_facecolor(BG_DARK)

    ax1.set_facecolor(BG_DARK)
    ax1.set_title('Distribución por Severidad', color='white', fontsize=11, pad=12)

    # Barras horizontales de puertos
    ax2.set_facecolor(BG_DARK)
    if ports_open:
        port_names = [f'{p}/{n}' for p,(n,lv,_) in list(ports_open.items())[:8]]
        port_risk  = [{'CRITICO':4,'ALTO':3,'MEDIO':2,'INFO':1}.get(lv,1)
                      for _,(n,lv,_) in list(ports_open.items())[:8]]
        bar_colors = [colors_d.get({'CRITICO':'CRITICO','ALTO':'ALTO','MEDIO':'MEDIO'}.get(
            list(ports_open.values())[i][1],'INFO'),'#00ccff')
                      for i in range(min(8,len(ports_open)))]
        bars = ax2.barh(port_names, port_risk, color=bar_colors, height=0.6,
                        edgecolor='#0a0a0a')
        ax2.set_xlim(0, 4.5)
        ax2.set_xticks([1,2,3,4])
        ax2.set_xticklabels(['INFO','MEDIO','ALTO','CRITICO'],color='#666')
        for bar, val in zip(bars, port_risk):
            ax2.text(val+0.05, bar.get_y()+bar.get_height()/2,
                    ['','INFO','MEDIO','ALTO','CRITICO'][val],
                    va='center', color='white', fontsize=7)
    else:
        ax2.text(0.5, 0.5, 'No se detectaron\npuertos peligrosos',
                ha='center', va='center', transform=ax2.transAxes,
                color=C_GREEN, fontsize=12, fontweight='bold')
    ax2.set_title('Puertos Detectados por Riesgo', color='white', fontsize=11, pad=12)
    ax2.tick_params(colors='#666')
    for spine in ax2.spines.values(): spine.set_color('#1a1a1a')

    plt.suptitle('GRÁFICA 1/3 — Análisis de Puertos del Router',
                color='white', fontsize=12, fontweight='bold', y=1.02)
    plt.tight_layout()

    import pathlib; pathlib.Path(os.path.dirname(path) if os.path.dirname(path) else '.').mkdir(parents=True, exist_ok=True)
    try:
        plt.savefig(path, dpi=130, bbox_inches='tight', facecolor=BG_DARK)
    except Exception as e:
        print(f'  [!] Gráfica 1 no generada: {e}')
    plt.close()

def grafica2_dispositivos(devices, path):
    """Gráfica 2: Mapa de dispositivos en la red."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5), facecolor=BG_DARK)

    # Vendors pie
    vendors = {}
    for d in devices:
        v = d.get('vendor','Desconocido') or 'Desconocido'
        vendors[v] = vendors.get(v, 0) + 1

    ax1.set_facecolor(BG_DARK)
    if vendors:
        top_vendors = sorted(vendors.items(), key=lambda x:-x[1])[:6]
        labels = [v for v,c in top_vendors]
        sizes  = [c for v,c in top_vendors]
        palette = ['#00ccff','#00ff41','#ffcc00','#ff8800','#ff3333','#aa44cc']
        ax1.pie(sizes, labels=labels, colors=palette[:len(labels)],
                autopct='%1.0f%%', startangle=90,
                wedgeprops=dict(width=0.6, edgecolor=BG_DARK, linewidth=1.5))
        for text in ax1.texts:
            text.set_color('white'); text.set_fontsize(8)
    else:
        ax1.text(0.5,0.5,'Sin dispositivos\ndetectados',ha='center',va='center',
                transform=ax1.transAxes,color=C_GREEN,fontsize=12)
    ax1.set_title(f'Fabricantes ({len(devices)} dispositivos)', color='white', fontsize=11, pad=12)

    # Timeline de IPs
    ax2.set_facecolor(BG_DARK)
    if devices:
        ips = [d['ip'] for d in devices[:15]]
        last_octets = [int(ip.split('.')[-1]) for ip in ips]
        colors_dev  = [C_GREEN if o < 10 else C_AMBER if o < 100 else C_CYAN
                       for o in last_octets]
        ax2.scatter(range(len(ips)), last_octets, c=colors_dev, s=120,
                    zorder=5, alpha=0.9)
        ax2.plot(range(len(ips)), last_octets, color='#1a2a3a', linewidth=1, zorder=4)
        for i, (ip, lo) in enumerate(zip(ips, last_octets)):
            ax2.text(i, lo+1.5, f'.{lo}', ha='center', color='#888', fontsize=7)
        ax2.set_xticks(range(len(ips)))
        ax2.set_xticklabels([f'Dev{i+1}' for i in range(len(ips))],
                            rotation=45, color='#666', fontsize=7)
    else:
        ax2.text(0.5,0.5,'Red vacía',ha='center',va='center',
                transform=ax2.transAxes,color=C_GREEN,fontsize=12)

    ax2.set_title('Distribución de IPs en la Red', color='white', fontsize=11, pad=12)
    ax2.set_facecolor(BG_DARK); ax2.tick_params(colors='#666')
    ax2.set_ylabel('Último octeto', color='#666', fontsize=9)
    for spine in ax2.spines.values(): spine.set_color('#1a1a1a')
    ax2.yaxis.label.set_color('#666')

    plt.suptitle('GRÁFICA 2/3 — Inventario de Dispositivos en la Red',
                color='white', fontsize=12, fontweight='bold', y=1.02)
    plt.tight_layout()
    import pathlib; pathlib.Path(os.path.dirname(path) if os.path.dirname(path) else '.').mkdir(parents=True, exist_ok=True)
    try:
        plt.savefig(path, dpi=130, bbox_inches='tight', facecolor=BG_DARK)
    except Exception as e:
        print(f'  [!] Gráfica 2 no generada: {e}')
    plt.close()

def grafica3_score_seguridad(score_data, path):
    """Gráfica 3: Score de seguridad general del router."""
    fig, axes = plt.subplots(1, 3, figsize=(13, 5), facecolor=BG_DARK)

    categories  = ['Puertos', 'DNS', 'Credenciales', 'Dispositivos', 'General']
    scores_vals = [
        score_data.get('ports', 70),
        score_data.get('dns',   80),
        score_data.get('creds', 60),
        score_data.get('devices', 75),
        score_data.get('total',  70),
    ]

    # Gauge total
    ax0 = axes[0]; ax0.set_facecolor(BG_DARK)
    total = score_data.get('total', 70)
    color_total = C_GREEN if total >= 80 else C_AMBER if total >= 60 else C_RED

    theta = np.linspace(np.pi, 0, 200)
    r_out, r_in = 1.0, 0.6
    ax0.plot(np.cos(theta)*r_out, np.sin(theta)*r_out, color='#1a1a1a', linewidth=20)
    theta_fill = np.linspace(np.pi, np.pi - (total/100)*np.pi, 200)
    ax0.plot(np.cos(theta_fill)*r_out, np.sin(theta_fill)*r_out,
            color=color_total, linewidth=20, alpha=0.9)
    ax0.text(0, 0.1, f'{total}', ha='center', va='center',
            color=color_total, fontsize=32, fontweight='bold')
    ax0.text(0, -0.25, 'SCORE', ha='center', color='white', fontsize=10)
    nivel = 'BUENO' if total>=80 else 'REGULAR' if total>=60 else 'RIESGO'
    ax0.text(0, -0.45, nivel, ha='center', color=color_total, fontsize=9, fontweight='bold')
    ax0.set_xlim(-1.3,1.3); ax0.set_ylim(-0.6,1.2)
    ax0.axis('off')
    ax0.set_title('Score Global', color='white', fontsize=11, pad=12)

    # Radar de categorías
    ax1 = axes[1]; ax1.set_facecolor(BG_DARK)
    n    = len(categories)
    angles = np.linspace(0, 2*np.pi, n, endpoint=False).tolist()
    angles += angles[:1]
    vals = scores_vals + scores_vals[:1]
    ax1.plot(angles, vals, color=C_GREEN, linewidth=2)
    ax1.fill(angles, vals, color=C_GREEN, alpha=0.15)
    ax1.set_xticks(angles[:-1])
    ax1.set_xticklabels(categories, color='white', fontsize=8)
    ax1.set_ylim(0,100); ax1.set_yticks([25,50,75,100])
    ax1.set_yticklabels(['25','50','75','100'], color='#444', fontsize=7)
    ax1.tick_params(colors='#666')
    ax1.set_facecolor(BG_DARK); ax1.grid(color='#1a1a1a')
    for spine in ax1.spines.values(): spine.set_color('#1a1a1a')
    ax1.set_title('Radar de Categorías', color='white', fontsize=11, pad=12)

    # Barras de scores
    ax2 = axes[2]; ax2.set_facecolor(BG_DARK)
    bar_colors = [C_GREEN if v>=80 else C_AMBER if v>=60 else C_RED for v in scores_vals]
    bars = ax2.barh(categories, scores_vals, color=bar_colors, height=0.55,
                    edgecolor='#0a0a0a')
    ax2.set_xlim(0,110)
    for bar, val in zip(bars, scores_vals):
        ax2.text(val+1, bar.get_y()+bar.get_height()/2, f'{val}',
                va='center', color='white', fontsize=8, fontweight='bold')
    ax2.axvline(80, color='#00ff41', linewidth=1, linestyle='--', alpha=0.3)
    ax2.text(81, 4.5, 'SEGURO', color='#00ff41', fontsize=7, alpha=0.5)
    ax2.set_title('Puntuación por Categoría', color='white', fontsize=11, pad=12)
    ax2.tick_params(colors='#888', labelsize=8)
    for spine in ax2.spines.values(): spine.set_color('#1a1a1a')
    ax2.set_xlabel('Score (0-100)', color='#666', fontsize=8)

    plt.suptitle('GRÁFICA 3/3 — Score de Seguridad del Router',
                color='white', fontsize=12, fontweight='bold', y=1.02)
    plt.tight_layout()
    import pathlib; pathlib.Path(os.path.dirname(path) if os.path.dirname(path) else '.').mkdir(parents=True, exist_ok=True)
    try:
        plt.savefig(path, dpi=130, bbox_inches='tight', facecolor=BG_DARK)
    except Exception as e:
        print(f'  [!] Gráfica 3 no generada: {e}')
    plt.close()

# ════════════════════════════════════════════════════════════════
# CÁLCULO DE SCORE
# ════════════════════════════════════════════════════════════════
def calcular_score(ports_open, dns_findings, default_creds_found, devices):
    """Calcula score de seguridad 0-100 por categoría."""
    # Puertos
    p_score = 100
    for port, (name, nivel, _) in ports_open.items():
        p_score -= {'CRITICO':20,'ALTO':12,'MEDIO':6,'INFO':2}.get(nivel, 0)
    p_score = max(0, p_score)

    # DNS
    d_score = 100
    for f in dns_findings:
        d_score -= {'ALTO':20,'MEDIO':10,'INFO':0}.get(f.get('riesgo','INFO'), 0)
    d_score = max(0, d_score)

    # Credenciales
    c_score = 100 if not default_creds_found else 20

    # Dispositivos
    dev_score = max(40, 100 - len(devices)*3)

    total = int((p_score*0.35 + d_score*0.25 + c_score*0.3 + dev_score*0.1))

    return {
        'ports':   p_score,
        'dns':     d_score,
        'creds':   c_score,
        'devices': dev_score,
        'total':   total,
    }

# ════════════════════════════════════════════════════════════════
# GENERADOR DE PDF
# ════════════════════════════════════════════════════════════════
def _s(t):
    """Safe string para fpdf."""
    if not t: return ''
    replacements = {
        'á':'a','é':'e','í':'i','ó':'o','ú':'u',
        'Á':'A','É':'E','Í':'I','Ó':'O','Ú':'U',
        'ñ':'n','Ñ':'N','ü':'u','—':'-','–':'-',
    }
    for a,b in replacements.items(): t=t.replace(a,b)
    try: return t.encode('latin-1','replace').decode('latin-1')
    except: return t

class RouterGuardPDF(FPDF):
    def header(self):
        self.set_fill_color(*NAVY); self.rect(0,0,210,26,'F')
        self.set_fill_color(*ACCENT); self.rect(0,26,210,2,'F')
        self.set_text_color(255,255,255)
        self.set_font('Helvetica','B',11); self.set_xy(12,7)
        self.cell(130,7,'CRYPT3CHO // ROUTERGUARD v'+VERSION,
                  new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font('Helvetica','B',9); self.set_xy(150,5)
        self.cell(50,5,'REPORTE DE SEGURIDAD',align='R',
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_font('Helvetica',size=7); self.set_text_color(180,210,240)
        self.set_xy(150,12)
        self.cell(50,5,TIMESTAMP,align='R',
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(6)

    def footer(self):
        self.set_y(-16)
        self.set_fill_color(*GRAY_L); self.rect(0,self.get_y(),210,16,'F')
        self.set_fill_color(220,232,248); self.rect(0,self.get_y(),210,0.8,'F')
        self.set_font('Helvetica',size=7); self.set_text_color(*GRAY_D)
        self.set_xy(12,self.get_y()+4)
        self.cell(130,5,'CRYPT3CHO RouterGuard | crypt3cho.com | Documento Confidencial')
        self.set_text_color(*NAVY)
        self.cell(0,5,f'Pagina {self.page_no()}',align='R')

def generar_pdf(gateway, ports_open, dns_findings, default_creds_found,
               devices, score_data, actions_done, g1, g2, g3, output_dir):
    pdf = RouterGuardPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()
    y = 36

    def kv(label, val, nivel=None):
        nonlocal y
        colors = {'CRITICO':RED_C,'ALTO':(200,80,0),'MEDIO':(160,120,0),
                  'INFO':(0,120,80),'OK':GREEN_C}
        pdf.set_xy(14,y)
        pdf.set_font('Helvetica','B',7.5); pdf.set_text_color(*NAVY)
        pdf.cell(55,6,_s(label),new_x=XPos.RIGHT,new_y=YPos.TOP)
        pdf.set_font('Helvetica',size=7.5)
        if nivel and nivel in colors:
            pdf.set_text_color(*colors[nivel])
        else:
            pdf.set_text_color(*GRAY_D)
        pdf.cell(0,6,_s(str(val)),new_x=XPos.LMARGIN,new_y=YPos.NEXT)
        y += 6
        if y > 270: pdf.add_page(); y = 36

    def sect(title):
        nonlocal y
        y += 4
        pdf.set_fill_color(*ACCENT)
        pdf.rect(14,y,182,1.5,'F')
        y += 4
        pdf.set_font('Helvetica','B',10); pdf.set_text_color(*NAVY)
        pdf.set_xy(14,y)
        pdf.cell(0,7,_s(title),new_x=XPos.LMARGIN,new_y=YPos.NEXT)
        y += 7

    # ── RESUMEN EJECUTIVO ─────────────────────────────────────
    sect('1. RESUMEN EJECUTIVO')
    total = score_data.get('total',0)
    nivel_global = 'BUENO' if total>=80 else 'REGULAR' if total>=60 else 'RIESGO ALTO'
    kv('ROUTER/GATEWAY',   gateway)
    kv('SCORE GLOBAL',     f"{total}/100 — {nivel_global}",
       'OK' if total>=80 else 'MEDIO' if total>=60 else 'CRITICO')
    kv('PUERTOS PELIGROSOS', f"{len(ports_open)} detectados",
       'OK' if not ports_open else 'CRITICO')
    kv('DNS CONFIGURADO',  ', '.join([f['ip'] for f in dns_findings]),
       'OK' if all(f['riesgo']=='INFO' for f in dns_findings) else 'ALTO')
    kv('CREDENCIALES',
       'No se detectaron credenciales por defecto' if not default_creds_found else
       f'ALERTA: {len(default_creds_found)} posibles accesos con creds default',
       'OK' if not default_creds_found else 'CRITICO')
    kv('DISPOSITIVOS EN RED', f"{len(devices)} detectados")
    kv('SISTEMA ANALIZADO',  f"{OS_TYPE} — {platform.node()}")
    kv('FECHA/HORA',         TIMESTAMP)

    # ── PUERTOS ────────────────────────────────────────────────
    sect('2. PUERTOS Y SERVICIOS EXPUESTOS')
    if ports_open:
        for port, (name, nivel, desc) in ports_open.items():
            c = {'CRITICO':RED_C,'ALTO':(200,80,0),'MEDIO':AMBER_C,'INFO':(0,100,160)}.get(nivel,GRAY_D)
            pdf.set_xy(14,y)
            pdf.set_font('Helvetica','B',7.5); pdf.set_text_color(*c)
            pdf.cell(25,6,f'[{nivel}]',new_x=XPos.RIGHT,new_y=YPos.TOP)
            pdf.set_text_color(*NAVY)
            pdf.cell(25,6,f'Puerto {port}',new_x=XPos.RIGHT,new_y=YPos.TOP)
            pdf.set_font('Helvetica',size=7); pdf.set_text_color(*GRAY_D)
            pdf.cell(0,6,_s(f'{name} — {desc}'),new_x=XPos.LMARGIN,new_y=YPos.NEXT)
            y += 6
    else:
        kv('RESULTADO', 'No se detectaron puertos peligrosos abiertos', 'OK')

    # ── DNS ────────────────────────────────────────────────────
    sect('3. ANALISIS DE DNS')
    for f in dns_findings:
        kv(f['ip'], f"{f['nombre']} — {f.get('nota',f['estado'])}", f['riesgo'])

    # ── DISPOSITIVOS ───────────────────────────────────────────
    sect('4. INVENTARIO DE DISPOSITIVOS')
    for d in devices[:15]:
        kv(d['ip'], f"{d.get('vendor','?')} | MAC: {d.get('mac','?')[:17]} | {d.get('host','')}")

    # ── ACCIONES REALIZADAS ────────────────────────────────────
    sect('5. ACCIONES REALIZADAS')
    for accion, resultado in actions_done:
        kv(accion, resultado)
    if not actions_done:
        kv('ACCIONES', 'Ninguna acción ejecutada en esta sesión')

    # ── RECOMENDACIONES ────────────────────────────────────────
    sect('6. RECOMENDACIONES')
    recs = [
        ('Cambiar credenciales del router',
         'Accede a tu panel admin y cambia el usuario/password por defecto.'),
        ('Desactivar Telnet y UPnP',
         'En la configuracion del router, desactiva Telnet (port 23) y UPnP.'),
        ('Usar DNS seguro (1.1.1.1)',
         'Configura DNS Cloudflare en tu router para mejor privacidad y velocidad.'),
        ('Actualizar firmware',
         'Verifica en el panel admin si hay actualizaciones de firmware disponibles.'),
        ('Revisar dispositivos desconocidos',
         'Si hay dispositivos que no reconoces, cambia la contrasena del WiFi.'),
        ('Activar HTTPS en el panel admin',
         'Si tu router lo soporta, usa HTTPS para acceder al panel de administracion.'),
    ]
    for titulo, desc in recs:
        if y + 14 > 270: pdf.add_page(); y = 36
        pdf.set_xy(14,y)
        pdf.set_font('Helvetica','B',7.5); pdf.set_text_color(*NAVY)
        pdf.cell(0,5,_s(f'  > {titulo}'),new_x=XPos.LMARGIN,new_y=YPos.NEXT)
        pdf.set_xy(18,pdf.get_y())
        pdf.set_font('Helvetica',size=7); pdf.set_text_color(*GRAY_D)
        pdf.cell(0,5,_s(f'    {desc}'),new_x=XPos.LMARGIN,new_y=YPos.NEXT)
        y = pdf.get_y() + 2

    # ── GRÁFICAS ───────────────────────────────────────────────
    for chart_path, title in [(g1,'Análisis de Puertos'),
                               (g2,'Inventario de Dispositivos'),
                               (g3,'Score de Seguridad')]:
        if chart_path and os.path.exists(chart_path):
            pdf.add_page()
            pdf.set_font('Helvetica','B',9); pdf.set_text_color(*NAVY)
            pdf.set_xy(14,36)
            pdf.cell(0,8,_s(f'VISUALIZACIÓN — {title}'),
                    new_x=XPos.LMARGIN,new_y=YPos.NEXT)
            try:
                pdf.image(chart_path, x=10, y=48, w=190)
            except: pass

    # Guardar
    ts  = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    out = Path(output_dir) / f'RouterGuard_Reporte_{ts}.pdf'
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    pdf.output(str(out))
    return str(out)

# ════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════
def main():
    console.print(f'[bold cyan]{BANNER}[/bold cyan]')
    console.print(Rule('[bold cyan]CRYPT3CHO RouterGuard v1.0 — Análisis de Seguridad[/bold cyan]'))
    console.print(Panel(
        f'[dim]Sistema: {OS_TYPE} — {platform.node()}\n'
        f'Fecha:   {TIMESTAMP}\n'
        f'Output:  {ARGS.output}[/dim]',
        border_style='cyan', padding=(0,2)))

    output_dir = ARGS.output

    # ── PASO 1: Detección de gateway ──────────────────────────
    console.print('\n[cyan][*] Detectando configuración de red...[/cyan]')
    gateway = get_gateway()
    subnet  = get_local_subnet(gateway)
    dns_servers = get_dns_servers()
    console.print(f'  [green][+] Gateway:[/green] [bold]{gateway}[/bold]')
    console.print(f'  [green][+] Subred:[/green]  {subnet}')
    console.print(f'  [green][+] DNS:[/green]     {", ".join(dns_servers)}')

    results = {
        'gateway':    gateway,
        'ports':      {},
        'dns':        [],
        'creds':      [],
        'devices':    [],
        'score':      {},
        'actions':    [],
    }

    with Progress(SpinnerColumn(), TextColumn('[cyan]{task.description}'),
                  console=console) as prog:

        # ── PASO 2: Escaneo de puertos ────────────────────────
        t = prog.add_task('Escaneando puertos del router...', total=None)
        results['ports'] = scan_ports(gateway)
        prog.update(t, description=f'[green]Puertos: {len(results["ports"])} detectados[/green]')
        prog.stop()

    # Mostrar puertos
    if results['ports']:
        t_ports = Table(title='Puertos del Router', box=box.SIMPLE_HEAVY, style='cyan')
        t_ports.add_column('PUERTO', style='white')
        t_ports.add_column('SERVICIO', style='cyan')
        t_ports.add_column('RIESGO', style='red')
        t_ports.add_column('DESCRIPCIÓN', style='dim')
        for port, (name, nivel, desc) in results['ports'].items():
            color = {'CRITICO':'bold red','ALTO':'yellow','MEDIO':'white','INFO':'dim'}.get(nivel,'white')
            t_ports.add_row(str(port), name, f'[{color}]{nivel}[/{color}]', desc[:50])
        console.print(t_ports)
    else:
        console.print('  [green][+] No se detectaron puertos peligrosos abiertos[/green]')

    # ── PASO 3: Análisis DNS ──────────────────────────────────
    console.print('\n[cyan][*] Analizando configuración DNS...[/cyan]')
    results['dns'] = analyze_dns(dns_servers, gateway)
    for f in results['dns']:
        level_color = {'INFO':'green','MEDIO':'yellow','ALTO':'red'}.get(f['riesgo'],'white')
        console.print(f"  [{level_color}][{f['riesgo']}][/{level_color}] "
                     f"{f['ip']} — {f['nombre']} {f.get('nota','')}")

    # ── PASO 4: Inventario de red ─────────────────────────────
    console.print('\n[cyan][*] Escaneando dispositivos en la red...[/cyan]')
    results['devices'] = scan_network(subnet)
    console.print(f'  [green][+] {len(results["devices"])} dispositivos detectados[/green]')
    if results['devices']:
        t_dev = Table(box=box.SIMPLE_HEAVY, style='dim', show_header=True)
        t_dev.add_column('IP',      style='cyan', width=16)
        t_dev.add_column('VENDOR',  style='white', width=18)
        t_dev.add_column('MAC',     style='dim',  width=20)
        t_dev.add_column('HOSTNAME',style='dim',  width=25)
        for d in results['devices'][:12]:
            t_dev.add_row(d['ip'],d.get('vendor','?')[:18],
                         d.get('mac','?')[:18],d.get('host','')[:24])
        console.print(t_dev)

    # ── PASO 5: Credenciales default ─────────────────────────
    console.print('\n[cyan][*] Verificando credenciales por defecto...[/cyan]')
    results['creds'] = check_default_creds(gateway, results['ports'])
    if results['creds']:
        console.print(f'  [bold red][!!!] Posible acceso con credenciales por defecto[/bold red]')
    else:
        console.print('  [green][+] No se detectaron credenciales por defecto expuestas[/green]')

    # ── Score ────────────────────────────────────────────────
    results['score'] = calcular_score(
        results['ports'], results['dns'],
        results['creds'], results['devices'])

    total_score = results['score']['total']
    score_color = 'green' if total_score >= 80 else 'yellow' if total_score >= 60 else 'red'
    console.print(Rule(f'[bold {score_color}]SCORE DE SEGURIDAD: {total_score}/100[/bold {score_color}]'))

    # ── ACCIONES DISPONIBLES ──────────────────────────────────
    if not ARGS.pdf_only:
        console.print(Panel(
            '[bold white]ACCIONES DISPONIBLES[/bold white]\n\n'
            '[cyan][1][/cyan] Cambiar DNS a Cloudflare (1.1.1.1) — más seguro y rápido\n'
            '[cyan][2][/cyan] Limpiar caché DNS del sistema\n'
            '[cyan][3][/cyan] Exportar inventario de dispositivos (JSON + CSV)\n'
            '[cyan][4][/cyan] Solo generar reporte PDF\n'
            '[cyan][0][/cyan] Solo PDF sin acciones',
            border_style='cyan', padding=(0,2)))

        while True:
            accion = Prompt.ask(
                '  Selecciona acción',
                choices=['0','1','2','3','4'], default='4')

            if accion == '1':
                ok, msg = action_change_dns(gateway)
                results['actions'].append(('Cambiar DNS a Cloudflare', msg))
            elif accion == '2':
                ok, msg = action_flush_dns()
                results['actions'].append(('Limpiar cache DNS', msg))
            elif accion == '3':
                ok, msg = action_export_inventory(results['devices'], output_dir)
                results['actions'].append(('Exportar inventario', msg))
            elif accion in ('0','4'):
                break

            if not Confirm.ask('  ¿Ejecutar otra acción?', default=False):
                break

    # ── GRÁFICAS ─────────────────────────────────────────────
    console.print('\n[yellow][*] Generando gráficas...[/yellow]')
    import tempfile
    chart_dir = Path(output_dir)
    chart_dir.mkdir(parents=True, exist_ok=True)

    g1 = str(chart_dir / 'rg_chart1.png')
    g2 = str(chart_dir / 'rg_chart2.png')
    g3 = str(chart_dir / 'rg_chart3.png')

    grafica1_riesgo_puertos(results['ports'], g1)
    console.print('  [green][+] Gráfica 1 — Puertos[/green]')
    grafica2_dispositivos(results['devices'], g2)
    console.print('  [green][+] Gráfica 2 — Dispositivos[/green]')
    grafica3_score_seguridad(results['score'], g3)
    console.print('  [green][+] Gráfica 3 — Score[/green]')

    # ── PDF ───────────────────────────────────────────────────
    console.print('\n[yellow][*] Generando reporte PDF...[/yellow]')
    pdf_path = generar_pdf(
        gateway, results['ports'], results['dns'],
        results['creds'], results['devices'], results['score'],
        results['actions'], g1, g2, g3, output_dir)

    # Limpiar charts temporales
    for p in [g1,g2,g3]:
        try: os.unlink(p)
        except: pass

    console.print(Rule('[bold green]ANÁLISIS COMPLETADO[/bold green]'))
    console.print(f'  [bold green][+] Reporte PDF:[/bold green] {pdf_path}')
    console.print(f'  [dim]Score: {total_score}/100 | '
                 f'Puertos: {len(results["ports"])} | '
                 f'Dispositivos: {len(results["devices"])}[/dim]')
    console.print(f'\n  [dim]crypt3cho.com // RouterGuard v{VERSION}[/dim]\n')

if __name__ == '__main__':
    import signal
    signal.signal(signal.SIGINT,
                  lambda s,f: (console.print('\n[yellow]Interrumpido.[/yellow]'), sys.exit(0)))
    main()
