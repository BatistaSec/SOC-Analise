import socket
import requests
import time
import logging
import sys
import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
import re
import platform
from tkinter import ttk
from PIL import Image, ImageTk
import itertools

# Configuração do logger para simular envio ao SIEM via syslog UDP
class SyslogHandler(logging.Handler):
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    def emit(self, record):
        msg = self.format(record)
        self.sock.sendto(msg.encode(), (self.host, self.port))

# Configuração do SIEM (exemplo: localhost:514)
SIEM_HOST = '127.0.0.1'
SIEM_PORT = 514
logger = logging.getLogger('SIEM')
logger.setLevel(logging.INFO)
logger.addHandler(SyslogHandler(SIEM_HOST, SIEM_PORT))

# Detecta SO para comando de ping
IS_WINDOWS = platform.system().lower().startswith('win')

def validar_ip(ip):
    # Regex simples para IPv4
    return re.match(r'^([0-9]{1,3}\.){3}[0-9]{1,3}$', ip) is not None

def validar_url(url):
    return url.startswith('http://') or url.startswith('https://')

def validar_portas(portas_str):
    try:
        portas = [int(p.strip()) for p in portas_str.split(',') if p.strip().isdigit()]
        return portas if portas else None
    except:
        return None

# Ajuste do comando de ping para multiplataforma
def ping_host(host):
    if IS_WINDOWS:
        return os.system(f'ping -n 1 {host} >nul')
    else:
        return os.system(f'ping -c 1 {host} >/dev/null 2>&1')

# 1. Explorar ataques de rede (scan de portas)
def port_scan(target, ports=[22, 80, 443, 3389]):
    results = {}
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            sock.connect((target, port))
            results[port] = 'open'
            logger.info(f'Porta aberta detectada: {target}:{port}')
        except:
            results[port] = 'closed'
        finally:
            sock.close()
    return results

# 2. Explorar ataques web (requisições HTTP)
def web_explore(url):
    try:
        resp = requests.get(url, timeout=3)
        if resp.status_code == 200:
            if 'admin' in resp.text.lower() or 'error' in resp.text.lower():
                logger.warning(f'Possível endpoint sensível ou erro em {url}')
        else:
            logger.warning(f'Resposta HTTP suspeita {resp.status_code} em {url}')
    except Exception as e:
        logger.error(f'Erro ao acessar {url}: {e}')

# 3. Monitorar endpoint (ping e serviço web)
def monitor_endpoint(host, url=None):
    # Ping
    response = ping_host(host)
    if response == 0:
        logger.info(f'Host {host} está online')
    else:
        logger.error(f'Host {host} está offline')
    # Serviço web
    if url:
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200:
                logger.info(f'Serviço web {url} está online')
            else:
                logger.warning(f'Serviço web {url} retornou {r.status_code}')
        except Exception as e:
            logger.error(f'Erro ao acessar serviço web {url}: {e}')

def run_port_scan_ui(target, ports, output_widget):
    enable_output()
    output_widget.insert(tk.END, f'Iniciando scan de portas em {target}...\n')
    results = port_scan(target, ports)
    for port, status in results.items():
        output_widget.insert(tk.END, f'Porta {port}: {status}\n')
    output_widget.insert(tk.END, '\n')
    output_widget.see(tk.END)
    disable_output()
    set_status('Scan de portas finalizado!', '#00ffae')
    stop_animation()

def run_web_explore_ui(url, output_widget):
    enable_output()
    output_widget.insert(tk.END, f'Explorando {url}...\n')
    try:
        resp = requests.get(url, timeout=3)
        output_widget.insert(tk.END, f'Status HTTP: {resp.status_code}\n')
        if resp.status_code == 200:
            if "admin" in resp.text.lower() or "error" in resp.text.lower():
                output_widget.insert(tk.END, 'Possível endpoint sensível ou erro detectado!\n')
        else:
            output_widget.insert(tk.END, f'Resposta HTTP suspeita: {resp.status_code}\n')
    except Exception as e:
        output_widget.insert(tk.END, f'Erro ao acessar {url}: {e}\n')
    output_widget.insert(tk.END, '\n')
    output_widget.see(tk.END)
    disable_output()
    set_status('Exploração web finalizada!', '#00ffae')
    stop_animation()

def run_monitor_endpoint_ui(host, url, output_widget):
    enable_output()
    output_widget.insert(tk.END, f'Monitorando {host}...\n')
    response = ping_host(host)
    if response == 0:
        output_widget.insert(tk.END, f'Host {host} está online\n')
    else:
        output_widget.insert(tk.END, f'Host {host} está offline\n')
    if url:
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200:
                output_widget.insert(tk.END, f'Serviço web {url} está online\n')
            else:
                output_widget.insert(tk.END, f'Serviço web {url} retornou {r.status_code}\n')
        except Exception as e:
            output_widget.insert(tk.END, f'Erro ao acessar serviço web {url}: {e}\n')
    output_widget.insert(tk.END, '\n')
    output_widget.see(tk.END)
    disable_output()
    set_status('Monitoramento finalizado!', '#00ffae')
    stop_animation()

# Interface gráfica aprimorada
if __name__ == '__main__':
    import os
    import threading

    # Variáveis globais para animação
    anim_label = None
    anim_running = False
    anim_cycle = None

    def start_thread(target, *args):
        Thread(target=target, args=args, daemon=True).start()

    def limpar_output():
        output.configure(state='normal')
        output.delete(1.0, tk.END)
        output.configure(state='disabled')
        set_status('', '#00e0ff')
        stop_animation()

    def scan_btn():
        host = entry_host.get().strip()
        portas = validar_portas(entry_ports.get())
        if not host:
            set_status('Informe um IP ou domínio válido!', 'red')
            return
        if not portas:
            set_status('Informe portas válidas!', 'red')
            return
        set_status('Executando scan de portas...', 'blue')
        start_animation('scan')
        start_thread(run_port_scan_ui, host, portas, output)

    def web_btn():
        url = entry_url.get().strip()
        if not validar_url(url):
            set_status('Informe uma URL válida (http/https)!', 'red')
            return
        set_status('Explorando web...', 'blue')
        start_animation('web')
        start_thread(run_web_explore_ui, url, output)

    def monitor_btn():
        host = entry_host.get().strip()
        url = entry_url.get().strip()
        if not host:
            set_status('Informe um IP ou domínio válido!', 'red')
            return
        if url and not validar_url(url):
            set_status('Informe uma URL válida (http/https)!', 'red')
            return
        set_status('Monitorando endpoint...', 'blue')
        start_animation('monitor')
        start_thread(run_monitor_endpoint_ui, host, url, output)

    def set_status(msg, color):
        status_label.config(text=msg, fg=color)

    # Ícones (exemplo: use imagens PNG pequenas na mesma pasta do script)
    def load_icon(path, size=(32,32)):
        try:
            img = Image.open(path).resize(size, Image.ANTIALIAS)
            return ImageTk.PhotoImage(img)
        except:
            return None

    icon_scan = load_icon('icon_scan.png')
    icon_web = load_icon('icon_web.png')
    icon_monitor = load_icon('icon_monitor.png')
    icon_clear = load_icon('icon_clear.png')
    icon_logo = load_icon('icon_soc.png', (64,64))

    # Animação simples (círculo girando)
    anim_frames = []
    try:
        for i in range(1, 9):
            anim_frames.append(ImageTk.PhotoImage(Image.open(f'anim{i}.png').resize((40,40), Image.ANTIALIAS)))
    except:
        anim_frames = []

    def start_animation(tipo):
        global anim_running, anim_cycle
        if not anim_frames:
            return
        anim_running = True
        if anim_label:
            anim_label.place(x=690, y=10)
        def animate():
            for frame in itertools.cycle(anim_frames):
                if not anim_running:
                    break
                anim_label.config(image=frame)
                root.update_idletasks()
                root.after(80)
        anim_cycle = threading.Thread(target=animate, daemon=True)
        anim_cycle.start()

    def stop_animation():
        global anim_running
        anim_running = False
        if anim_label:
            anim_label.config(image='')

    root = tk.Tk()
    root.title('SOC Monitor - Visual')
    root.geometry('800x650')
    root.configure(bg='#181c2b')

    style = ttk.Style()
    style.theme_use('clam')
    style.configure('TButton', font=('Segoe UI', 11, 'bold'), background='#2d3250', foreground='white')
    style.configure('TLabel', background='#181c2b', foreground='#e0e0e0', font=('Segoe UI', 11))
    style.configure('TEntry', font=('Segoe UI', 11))

    # Logo
    if icon_logo:
        logo_label = tk.Label(root, image=icon_logo, bg='#181c2b')
        logo_label.pack(pady=(10, 0))

    title = tk.Label(root, text='SOC Monitor', font=('Segoe UI', 22, 'bold'), bg='#181c2b', fg='#00e0ff')
    title.pack(pady=(5, 5))

    subtitle = tk.Label(root, text='Ferramenta visual para análise e monitoramento de segurança', font=('Segoe UI', 12), bg='#181c2b', fg='#b0b0b0')
    subtitle.pack(pady=(0, 15))

    form_frame = tk.Frame(root, bg='#181c2b')
    form_frame.pack(pady=5)

    ttk.Label(form_frame, text='Alvo/IP:').grid(row=0, column=0, sticky='e', padx=5, pady=5)
    entry_host = ttk.Entry(form_frame, width=35)
    entry_host.insert(0, 'scanme.nmap.org')
    entry_host.grid(row=0, column=1, padx=5, pady=5)

    ttk.Label(form_frame, text='URL:').grid(row=1, column=0, sticky='e', padx=5, pady=5)
    entry_url = ttk.Entry(form_frame, width=35)
    entry_url.insert(0, 'http://scanme.nmap.org/')
    entry_url.grid(row=1, column=1, padx=5, pady=5)

    ttk.Label(form_frame, text='Portas (separadas por vírgula):').grid(row=2, column=0, sticky='e', padx=5, pady=5)
    entry_ports = ttk.Entry(form_frame, width=35)
    entry_ports.insert(0, '22,80,443,3389')
    entry_ports.grid(row=2, column=1, padx=5, pady=5)

    btn_frame = tk.Frame(root, bg='#181c2b')
    btn_frame.pack(pady=10)
    ttk.Button(btn_frame, text='Scan de Portas', image=icon_scan, compound=tk.LEFT if icon_scan else None, command=scan_btn).pack(side=tk.LEFT, padx=12)
    ttk.Button(btn_frame, text='Explorar Web', image=icon_web, compound=tk.LEFT if icon_web else None, command=web_btn).pack(side=tk.LEFT, padx=12)
    ttk.Button(btn_frame, text='Monitorar Endpoint', image=icon_monitor, compound=tk.LEFT if icon_monitor else None, command=monitor_btn).pack(side=tk.LEFT, padx=12)
    ttk.Button(btn_frame, text='Limpar', image=icon_clear, compound=tk.LEFT if icon_clear else None, command=limpar_output).pack(side=tk.LEFT, padx=12)

    output = scrolledtext.ScrolledText(root, width=90, height=20, font=('Consolas', 11), bg='#23263a', fg='#00ffae', insertbackground='white', borderwidth=2, relief='groove')
    output.pack(pady=10)
    output.configure(state='disabled')

    # Animação label
    anim_label = tk.Label(root, bg='#181c2b')
    anim_label.place(x=690, y=10)

    status_label = tk.Label(root, text='', font=('Segoe UI', 11, 'bold'), bg='#181c2b', fg='#00e0ff')
    status_label.pack(pady=(0, 10))

    instrucao = tk.Label(root, text='Dica: Use IPs ou domínios válidos. Os resultados também são enviados ao SIEM (syslog UDP).', fg='#b0b0b0', bg='#181c2b', font=('Segoe UI', 10))
    instrucao.pack(pady=5)

    # Função para liberar output para escrita temporária
    def enable_output():
        output.configure(state='normal')
    def disable_output():
        output.configure(state='disabled')

    root.mainloop()
