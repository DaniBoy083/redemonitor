"""Aplicativo de monitoramento local de rede com interface Kivy.

Este modulo concentra quatro responsabilidades principais:
1. Descobrir sub-redes locais e dispositivos presentes via ARP.
2. Monitorar conexoes ativas da maquina local.
3. Registrar conexoes observadas em arquivo CSV.
4. Aplicar bloqueios locais de saida no Windows Firewall com base em IPs e dominios.

O foco e monitoramento local e apoio operacional. Ele nao substitui solucoes
centralizadas de firewall, proxy, NAC, DNS filtering ou SIEM.
"""

import csv
import concurrent.futures
import ctypes
import ipaddress
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

from kivy.app import App
from kivy.clock import Clock
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput

import psutil
import scapy.all as scapy


# Diretorio base do app.
# Em modo empacotado (PyInstaller), usamos a pasta do executavel para manter
# configuracoes e relatorios persistentes no dispositivo final.
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = Path(__file__).resolve().parent

# Arquivo de configuracao carregado a cada ciclo de atualizacao.
CONFIG_PATH = BASE_DIR / "monitor_config.json"

# Arquivo CSV que recebe novos acessos observados durante a execucao.
ACCESS_LOG_PATH = BASE_DIR / "access_log.csv"
REPORTS_DIR = BASE_DIR / "reports"

# Prefixo fixo para nomear regras criadas pelo aplicativo no Firewall do Windows.
APP_RULE_PREFIX = "DeteccaoRede"
APP_NAME = "MonitorRede"
APP_VERSION = "2.1.0"
APP_AUTHOR = "thefu"
APP_GITHUB_URL = "https://github.com/thefu"


# Configuracao padrao. Ela e usada tanto como fallback quando o JSON estiver
# invalido quanto como base para criar o arquivo de configuracao inicial.
DEFAULT_CONFIG = {
    "scan_interval_seconds": 5,
    "device_scan_interval_seconds": 30,
    "config_check_interval_seconds": 3,
    "scan_networks": ["auto"],
    "infrastructure_devices": [
        {"name": "Modem", "ip": "192.168.1.1"},
        {"name": "Repetidor", "ip": "192.168.1.2"},
    ],
    "restricted_domains": [],
    "restricted_ips": [],
    "connection_display_limit": 12,
    "enable_reverse_dns": False,
    "reverse_dns_ttl_seconds": 600,
    "enable_ping_fallback": True,
    "ping_timeout_ms": 300,
    "ping_sweep_limit": 128,
    "network_test_sample_size": 24,
    "network_test_full_max_hosts": 512,
}


PROFILE_PRESETS = {
    "normal": {
        "scan_interval_seconds": 5,
        "device_scan_interval_seconds": 30,
        "config_check_interval_seconds": 3,
        "connection_display_limit": 12,
        "enable_reverse_dns": True,
        "reverse_dns_ttl_seconds": 300,
        "enable_ping_fallback": True,
        "ping_timeout_ms": 350,
        "ping_sweep_limit": 192,
        "network_test_sample_size": 32,
        "network_test_full_max_hosts": 512,
    },
    "leve": {
        "scan_interval_seconds": 5,
        "device_scan_interval_seconds": 75,
        "config_check_interval_seconds": 5,
        "connection_display_limit": 6,
        "enable_reverse_dns": False,
        "reverse_dns_ttl_seconds": 600,
        "enable_ping_fallback": True,
        "ping_timeout_ms": 300,
        "ping_sweep_limit": 128,
        "network_test_sample_size": 24,
        "network_test_full_max_hosts": 384,
    },
    "economia_maxima": {
        "scan_interval_seconds": 8,
        "device_scan_interval_seconds": 120,
        "config_check_interval_seconds": 5,
        "connection_display_limit": 6,
        "enable_reverse_dns": False,
        "reverse_dns_ttl_seconds": 900,
        "enable_ping_fallback": True,
        "ping_timeout_ms": 250,
        "ping_sweep_limit": 96,
        "network_test_sample_size": 16,
        "network_test_full_max_hosts": 256,
    },
}


# Texto exibido na visao de ajuda interna do aplicativo. O objetivo e permitir
# consulta rapida sem depender do README aberto externamente.
HELP_TEXT = """=== AJUDA RAPIDA ===

Objetivo:
Monitorar redes locais, detectar hosts ativos, acompanhar conexoes da maquina local e aplicar bloqueios locais no Windows.

Arquivos principais:
- main.py: logica da aplicacao
- monitor_config.json: configuracao em uso pelo app
- monitor_config.example.jsonc: configuracao comentada para consulta
- access_log.csv: log de novas conexoes vistas durante a execucao

Como usar:
1. Ajuste modem, repetidor, redes e bloqueios em monitor_config.json.
2. Rode o app pela .venv.
3. Use o botao Config para editar o JSON dentro do proprio app.
4. Na aba Config, use os perfis Normal, Leve ou Economia Maxima com um clique.
5. Use o botao Abrir Log para abrir o CSV de acessos.
6. Use o botao Exportar Relatorio para gerar snapshot TXT/CSV.
7. Execute como Administrador se quiser aplicar bloqueios no Firewall.
8. Use o botao Privacidade para ver VPN ativa, IP publico e alertas de tunel.
9. Use Teste de Rede (amostra) e Teste Completo (faixa maior) para diagnostico.

Campos principais do monitor_config.json:
- scan_interval_seconds: intervalo entre ciclos.
- scan_networks: redes varridas; use auto para detectar sub-redes locais.
- infrastructure_devices: modem, repetidor ou outros equipamentos acompanhados por IP.
- restricted_domains: dominios para bloqueio local por resolucao DNS + Firewall.
- restricted_ips: IPs remotos bloqueados localmente.
- connection_display_limit: quantidade maxima de conexoes mostradas na tela.
- device_scan_interval_seconds: intervalo do scan ARP (mais alto = menos carga).
- enable_reverse_dns: habilita/desabilita lookup reverso de host remoto.
- view de privacidade: mostra status de tunel VPN e visibilidade de IP publico.
- enable_ping_fallback: tenta descobrir hosts por ping quando ARP falha.
- ping_sweep_limit/network_test_sample_size/network_test_full_max_hosts: controlam custo e alcance dos testes.

Limitacoes:
- O scan ARP nao atravessa roteadores.
- O monitoramento de conexoes e local a esta maquina.
- O bloqueio por dominio depende dos IPs resolvidos no momento.
- Para ambiente corporativo amplo, o ideal continua sendo DNS filtrado, proxy e firewall centralizado.
"""


def detect_vpn_interfaces():
    """Detecta interfaces com padrao tipico de tunel VPN."""
    keywords = (
        "vpn", "tun", "tap", "wireguard", "wg", "openvpn",
        "ppp", "l2tp", "ipsec", "utun", "zerotier", "tailscale",
    )
    vpn_names = []
    stats = psutil.net_if_stats()

    for name, interface_stats in stats.items():
        if not interface_stats.isup:
            continue
        lowered = name.lower()
        if any(token in lowered for token in keywords):
            vpn_names.append(name)

    return sorted(set(vpn_names))


def fetch_public_ip(timeout=3):
    """Obtém IP publico por consulta HTTPS com timeout curto."""
    endpoints = (
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
    )

    for endpoint in endpoints:
        try:
            with urllib.request.urlopen(endpoint, timeout=timeout) as response:
                value = response.read().decode("utf-8", errors="ignore").strip()
            ipaddress.ip_address(value)
            return value
        except (urllib.error.URLError, ValueError, OSError):
            continue

    return "Indisponivel"


def read_config_text():
    """Le o JSON de configuracao como texto bruto para o editor."""
    ensure_config_file()
    return CONFIG_PATH.read_text(encoding="utf-8")


def save_config_text(raw_text):
    """Valida e salva o JSON de configuracao digitado pelo usuario."""
    parsed = json.loads(raw_text)
    CONFIG_PATH.write_text(json.dumps(parsed, indent=2, ensure_ascii=False), encoding="utf-8")


def normalize_domain_input(raw_value):
    """Normaliza entrada de dominio para uso em restricted_domains."""
    if raw_value is None:
        return None

    value = raw_value.strip().lower()
    if not value:
        return None

    if value.startswith("http://"):
        value = value[7:]
    elif value.startswith("https://"):
        value = value[8:]

    value = value.split("/")[0]
    value = value.split("?")[0]
    value = value.split("#")[0]
    value = value.split(":")[0]
    value = value.strip(".")

    if not value or " " in value or "." not in value:
        return None

    return value


def ensure_config_file():
    """Garante que o arquivo de configuracao exista.

    Se o usuario ainda nao tiver criado o arquivo JSON, o app gera um arquivo
    inicial com valores padrao para que a execucao continue sem falhar.
    """
    if CONFIG_PATH.exists():
        return

    CONFIG_PATH.write_text(
        json.dumps(DEFAULT_CONFIG, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )



def load_config():
    """Carrega a configuracao do monitor a partir do JSON.

    O retorno sempre contem todas as chaves esperadas, porque o conteudo lido
    e mesclado com DEFAULT_CONFIG. Assim, o codigo nao depende de todas as
    chaves estarem explicitamente presentes no arquivo.
    """
    ensure_config_file()

    try:
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        config = DEFAULT_CONFIG.copy()

    merged = DEFAULT_CONFIG.copy()
    merged.update(config)
    return merged



def get_local_networks():
    """Descobre automaticamente as sub-redes IPv4 locais.

    O app percorre as interfaces reportadas pelo sistema operacional e converte
    cada combinacao IP + mascara em uma rede CIDR. Interfaces de loopback e
    enderecos APIPA sao ignorados porque nao representam a LAN corporativa.
    """
    networks = set()

    for interface_addresses in psutil.net_if_addrs().values():
        for address in interface_addresses:
            if address.family != socket.AF_INET:
                continue
            if not address.address or not address.netmask:
                continue
            if address.address.startswith("127.") or address.address.startswith("169.254."):
                continue

            try:
                interface = ipaddress.IPv4Interface(f"{address.address}/{address.netmask}")
            except ValueError:
                continue

            networks.add(str(interface.network))

    return sorted(networks)



def get_default_gateways():
    """Obtem os gateways padrao conhecidos pela pilha de roteamento.

    O Scapy expoe a tabela de rotas; quando a rota possui rede 0.0.0.0/0,
    tratamos o proximo salto como gateway padrao. Isso ajuda a destacar modem,
    roteador principal ou equipamento equivalente na interface.
    """
    gateways = set()

    for route in getattr(scapy.conf.route, "routes", []):
        try:
            network, netmask, gateway, _, _, _ = route
        except ValueError:
            continue

        if network == 0 and netmask == 0 and gateway and gateway != "0.0.0.0":
            gateways.add(gateway)

    return sorted(gateways)


def detect_connected_network_info():
    """Detecta a rede IPv4 atualmente conectada para monitoramento automatico.

    Retorna informacoes da interface mais provavel de estar ativa na LAN:
    - interface
    - local_ip
    - netmask
    - network_cidr
    - gateway
    """
    candidates = []

    for interface_name, interface_addresses in psutil.net_if_addrs().items():
        for address in interface_addresses:
            if address.family != socket.AF_INET:
                continue
            if not address.address or not address.netmask:
                continue
            if address.address.startswith("127.") or address.address.startswith("169.254."):
                continue

            try:
                interface = ipaddress.IPv4Interface(f"{address.address}/{address.netmask}")
            except ValueError:
                continue

            candidates.append(
                {
                    "interface": interface_name,
                    "local_ip": address.address,
                    "netmask": address.netmask,
                    "network_cidr": str(interface.network),
                    "network": interface.network,
                }
            )

    if not candidates:
        return None

    gateways = get_default_gateways()
    gateway_ip = gateways[0] if gateways else None

    if gateway_ip:
        try:
            gateway_addr = ipaddress.IPv4Address(gateway_ip)
        except ValueError:
            gateway_addr = None

        if gateway_addr is not None:
            for candidate in candidates:
                if gateway_addr in candidate["network"]:
                    candidate["gateway"] = gateway_ip
                    return candidate

    selected = candidates[0]
    selected["gateway"] = gateway_ip
    return selected



def resolve_scan_networks(config):
    """Resolve a lista final de sub-redes que serao varridas.

    O valor especial "auto" instrui o sistema a descobrir as redes locais em
    tempo real. Alem disso, o usuario pode informar redes extras no JSON,
    permitindo monitorar mais de um segmento ao mesmo tempo.
    """
    configured = config.get("scan_networks", ["auto"])
    networks = set()

    for item in configured:
        if item == "auto":
            connected = detect_connected_network_info()
            if connected is not None:
                networks.add(connected["network_cidr"])
            else:
                networks.update(get_local_networks())
            continue

        try:
            networks.add(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            continue

    return sorted(networks)



def scan_network(ip_range):
    """Executa uma varredura ARP em uma sub-rede e retorna IP/MAC encontrados.

    A tecnica usada e broadcast ARP. Ela funciona bem em redes locais de camada 2,
    mas nao atravessa roteadores. Por isso, cada segmento precisa ser escaneado
    separadamente.
    """
    devices = []
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    answered = scapy.srp(broadcast / arp_request, timeout=2, verbose=False)[0]

    for _, response in answered:
        devices.append({"ip": response.psrc, "mac": response.hwsrc, "discovery": "ARP"})

    return devices


def ping_host(ip_addr, timeout_ms):
    """Testa alcance de um host por ping com timeout curto."""
    if os.name == "nt":
        command = ["ping", "-n", "1", "-w", str(timeout_ms), ip_addr]
    else:
        timeout_seconds = max(1, int(timeout_ms / 1000))
        command = ["ping", "-c", "1", "-W", str(timeout_seconds), ip_addr]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return result.returncode == 0


def scan_network_ping_fallback(ip_range, timeout_ms=300, limit_hosts=128):
    """Descobre hosts ativos por ping quando ARP nao retorna resultados.

    Em fallback, o MAC pode nao estar disponivel; por isso marcamos com '-'.
    """
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError:
        return []

    hosts = [str(host) for host in network.hosts()]
    if limit_hosts > 0:
        hosts = hosts[:limit_hosts]

    discovered = []
    workers = min(32, max(4, len(hosts))) if hosts else 4

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(ping_host, ip_addr, timeout_ms): ip_addr
            for ip_addr in hosts
        }
        for future in concurrent.futures.as_completed(future_map):
            ip_addr = future_map[future]
            try:
                is_up = future.result()
            except Exception:
                is_up = False
            if is_up:
                discovered.append({"ip": ip_addr, "mac": "-", "discovery": "PING"})

    discovered.sort(key=lambda item: item["ip"])
    return discovered


def discover_devices_in_network(network, enable_ping_fallback=True, ping_timeout_ms=300, ping_sweep_limit=128):
    """Descobre dispositivos em uma rede usando ARP e fallback opcional por ping."""
    try:
        arp_devices = scan_network(network)
        if arp_devices:
            return arp_devices, None

        if enable_ping_fallback:
            ping_devices = scan_network_ping_fallback(
                network,
                timeout_ms=ping_timeout_ms,
                limit_hosts=ping_sweep_limit,
            )
            return ping_devices, None

        return [], None
    except Exception as error:
        return [], f"Falha ao varrer {network}: {error}"



def merge_devices(device_lists):
    """Combina resultados de multiplas varreduras sem duplicar IPs."""
    merged = {}

    for device_list in device_lists:
        for device in device_list:
            existing = merged.get(device["ip"])
            if existing is None:
                merged[device["ip"]] = device
                continue

            # Prefere dado de ARP quando houver, pois contem MAC confiavel.
            if existing.get("discovery") != "ARP" and device.get("discovery") == "ARP":
                merged[device["ip"]] = device

    return [merged[ip] for ip in sorted(merged)]



def resolve_domain_ips(domain):
    """Resolve um dominio para IPs IPv4.

    O bloqueio local por dominio e implementado via resolucao DNS seguida de
    bloqueio por IP no firewall. Isso e util, mas tem limitacoes naturais quando
    o servico usa CDN, balanceamento ou IPs dinamicos.
    """
    try:
        _, _, addresses = socket.gethostbyname_ex(domain)
    except socket.gaierror:
        return []

    return sorted(set(addresses))



def is_windows_admin():
    """Verifica se o processo atual esta elevado no Windows."""
    if os.name != "nt":
        return False

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False



def run_firewall_command(arguments):
    """Executa um comando do Firewall do Windows e retorna sucesso + saida."""
    result = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return result.returncode == 0, (result.stdout or result.stderr).strip()



def ensure_firewall_rule(rule_name, remote_ips):
    """Cria ou recria uma regra de bloqueio de saida baseada em IP remoto.

    Primeiro removemos a regra anterior com o mesmo nome. Depois recriamos a
    regra com a lista atual de IPs. Isso simplifica a sincronizacao entre o JSON
    de configuracao e o estado real do firewall.
    """
    run_firewall_command([
        "netsh",
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        f"name={rule_name}",
    ])

    success, output = run_firewall_command([
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={rule_name}",
        "dir=out",
        "action=block",
        "enable=yes",
        f"remoteip={','.join(remote_ips)}",
    ])
    return success, output



def apply_restrictions(config):
    """Aplica restricoes locais a partir da configuracao.

    O metodo suporta dois tipos de alvo:
    - IPs explicitos definidos em restricted_ips.
    - Dominios definidos em restricted_domains, convertidos para IPs.

    As regras sao locais a maquina em que o app roda. Nao ha enforcement
    distribuido para toda a rede.
    """
    restricted_domains = config.get("restricted_domains", [])
    restricted_ips = sorted(set(config.get("restricted_ips", [])))

    if not restricted_domains and not restricted_ips:
        return ["Bloqueios: nenhum alvo configurado."], False

    if os.name != "nt":
        return ["Bloqueios: suportados apenas no Windows."], False

    if not is_windows_admin():
        return ["Bloqueios: execute o app como Administrador para aplicar regras."], False

    messages = []

    if restricted_ips:
        success, _ = ensure_firewall_rule(f"{APP_RULE_PREFIX} Block IPs", restricted_ips)
        if success:
            messages.append(f"Bloqueios por IP ativos: {', '.join(restricted_ips)}")
        else:
            messages.append("Bloqueios por IP: falha ao criar regra no Firewall.")

    for domain in restricted_domains:
        resolved_ips = resolve_domain_ips(domain)
        if not resolved_ips:
            messages.append(f"Dominio sem resolucao para bloqueio: {domain}")
            continue

        success, _ = ensure_firewall_rule(
            f"{APP_RULE_PREFIX} Block Domain {domain}",
            resolved_ips,
        )
        if success:
            messages.append(f"Dominio bloqueado: {domain} -> {', '.join(resolved_ips[:4])}")
        else:
            messages.append(f"Falha ao bloquear dominio: {domain}")

    return messages, True



def reverse_lookup(ip_address):
    """Tenta resolver o IP remoto para um nome reverso, quando disponivel."""
    try:
        host, _, _ = socket.gethostbyaddr(ip_address)
    except (socket.herror, socket.gaierror, TimeoutError, OSError):
        host = "-"

    return host



def get_active_connections(limit, resolve_host):
    """Coleta conexoes de rede ativas da maquina local.

    O retorno e uma visao resumida para exibicao na interface. O filtro mantem
    estados mais uteis operacionalmente e limita o volume renderizado em tela.
    """
    connections = []
    process_name_cache = {}

    for connection in psutil.net_connections(kind="inet"):
        if not connection.raddr:
            continue
        if connection.status not in {"ESTABLISHED", "SYN_SENT", "CLOSE_WAIT"}:
            continue

        remote_ip = connection.raddr.ip
        remote_port = connection.raddr.port
        local_ip = connection.laddr.ip if connection.laddr else "-"
        local_port = connection.laddr.port if connection.laddr else "-"

        pid = connection.pid or 0
        if pid in process_name_cache:
            process_name = process_name_cache[pid]
        else:
            try:
                process_name = psutil.Process(pid).name() if pid else "system"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = "desconhecido"
            process_name_cache[pid] = process_name

        protocol = "TCP" if connection.type == socket.SOCK_STREAM else "UDP"
        connections.append(
            {
                "pid": pid,
                "process": process_name,
                "local": f"{local_ip}:{local_port}",
                "remote": f"{remote_ip}:{remote_port}",
                "remote_host": resolve_host(remote_ip),
                "status": connection.status,
                "protocol": protocol,
            }
        )

    connections.sort(key=lambda item: (item["process"], item["remote"]))
    return connections[:limit]



def ensure_access_log_header():
    """Cria o CSV de log com cabecalho, caso ainda nao exista."""
    if ACCESS_LOG_PATH.exists():
        return

    with ACCESS_LOG_PATH.open("w", newline="", encoding="utf-8") as log_file:
        writer = csv.writer(log_file)
        writer.writerow([
            "timestamp",
            "process",
            "protocol",
            "local",
            "remote",
            "remote_host",
            "status",
        ])



def log_new_connections(connection_cache, connections):
    """Registra apenas conexoes ainda nao vistas na execucao atual.

    connection_cache funciona como memoria de curto prazo para evitar gravar a
    mesma conexao repetidamente a cada ciclo da interface.
    """
    ensure_access_log_header()
    current_keys = set()
    rows_to_write = []

    for connection in connections:
        key = (
            connection["process"],
            connection["protocol"],
            connection["local"],
            connection["remote"],
            connection["status"],
        )
        current_keys.add(key)

        if key in connection_cache:
            continue

        rows_to_write.append([
            time.strftime("%Y-%m-%d %H:%M:%S"),
            connection["process"],
            connection["protocol"],
            connection["local"],
            connection["remote"],
            connection["remote_host"],
            connection["status"],
        ])

    if rows_to_write:
        with ACCESS_LOG_PATH.open("a", newline="", encoding="utf-8") as log_file:
            writer = csv.writer(log_file)
            writer.writerows(rows_to_write)

    # Remove do cache conexoes que ja nao existem mais e adiciona as atuais.
    connection_cache.intersection_update(current_keys)
    connection_cache.update(current_keys)



def summarize_infrastructure(devices, config):
    """Gera um resumo textual do estado de modem, repetidor e gateways.

    A identificacao depende do IP configurado em monitor_config.json. Se o IP
    nao responder ao scan ARP do segmento monitorado, o item e marcado como
    offline ou fora da sub-rede.
    """
    device_index = {device["ip"]: device for device in devices}
    gateways = set(get_default_gateways())
    lines = []

    for item in config.get("infrastructure_devices", []):
        name = item.get("name", "Infra")
        ip_address = item.get("ip", "-")
        device = device_index.get(ip_address)
        gateway_marker = " gateway" if ip_address in gateways else ""

        if device:
            lines.append(f"{name}: online | {ip_address} | {device['mac']}{gateway_marker}")
        else:
            lines.append(f"{name}: offline/fora da sub-rede | {ip_address}{gateway_marker}")

    if not lines and gateways:
        for gateway in gateways:
            device = device_index.get(gateway)
            if device:
                lines.append(f"Gateway detectado: {gateway} | {device['mac']}")
            else:
                lines.append(f"Gateway detectado: {gateway}")

    return lines or ["Infraestrutura: nenhum modem/repetidor configurado."]


def build_device_connection_summary(devices, connections):
    """Monta resumo de tipo de conexao por IP de dispositivo detectado.

    O tipo e derivado das conexoes locais observadas para o IP remoto do host:
    TCP/UDP + estado (por exemplo, ESTABLISHED).
    """
    device_ips = {item["ip"] for item in devices}
    summary = {ip_addr: set() for ip_addr in device_ips}

    for item in connections:
        remote = item.get("remote", "")
        remote_ip = remote.split(":", 1)[0] if ":" in remote else remote
        if remote_ip not in summary:
            continue
        summary[remote_ip].add(f"{item['protocol']}:{item['status']}")

    return {
        ip_addr: ", ".join(sorted(values)) if values else "Sem trafego local observado"
        for ip_addr, values in summary.items()
    }



class MonitorApp(BoxLayout):
    """Container principal da interface Kivy.

    A interface e intencionalmente simples: uma linha de status no topo e um
    painel com rolagem para exibir o relatorio consolidado de monitoramento.
    """

    def __init__(self, **kwargs):
        super().__init__(orientation="vertical", **kwargs)

        # Carregamos a configuracao logo no inicio para definir ritmo de scan,
        # limites de exibicao e politica de bloqueio.
        self.monitor_config = load_config()

        # Cache usado para evitar gravar as mesmas conexoes varias vezes no CSV.
        self.connection_cache = set()

        # Assinatura da configuracao de restricoes para evitar recriar regras de
        # firewall sem necessidade em todo ciclo da interface.
        self.last_restriction_signature = None
        self.last_restriction_refresh = 0.0
        self.restriction_messages = ["Bloqueios: aguardando validacao."]
        self.current_view = "monitor"
        self.last_snapshot = None
        self.privacy_snapshot = None
        self.last_network_test_lines = ["Teste de rede ainda nao executado."]

        # Estado de caches para reduzir trabalho pesado por ciclo.
        self.reverse_dns_cache = {}
        self.cached_networks = []
        self.cached_devices = []
        self.cached_scan_errors = []
        self.last_device_scan_at = 0.0
        self.last_connected_network = None

        # Controle de recarga de configuracao em disco.
        self.last_config_check_at = 0.0
        self.last_config_mtime = None
        self.loop_event = None
        self.last_privacy_refresh_at = 0.0
        self.network_test_running = False

        # Barra de status superior, usada para mostrar rapidamente o estado dos
        # bloqueios ou algum problema relevante de execucao.
        self.status_label = Label(
            text="Inicializando monitor corporativo...",
            size_hint=(1, None),
            height=36,
            halign="left",
            valign="middle",
        )
        self.status_label.bind(size=self._sync_status_text)
        self.add_widget(self.status_label)

        # Barra simples de navegacao entre a visao operacional e a ajuda.
        self.actions_scroll = ScrollView(
            size_hint=(1, None),
            height=48,
            do_scroll_x=True,
            do_scroll_y=False,
            bar_width=8,
        )
        top_actions = BoxLayout(
            size_hint_x=None,
            height=48,
            spacing=8,
            padding=[6, 4, 6, 4],
        )
        top_actions.bind(minimum_width=lambda inst, value: setattr(inst, "width", value))
        self.top_actions = top_actions

        self.monitor_button = Button(text="Monitor")
        self.help_button = Button(text="Ajuda")
        self.privacy_button = Button(text="Privacidade")
        self.config_button = Button(text="Config")
        self.save_config_button = Button(text="Salvar Config")
        self.reload_config_button = Button(text="Recarregar Config")
        self.open_log_button = Button(text="Abrir Log")
        self.network_test_button = Button(text="Teste de Rede")
        self.network_test_full_button = Button(text="Teste Completo")
        self.export_report_button = Button(text="Exportar Relatorio")
        self.profile_normal_button = Button(text="Perfil Normal")
        self.profile_leve_button = Button(text="Perfil Leve")
        self.profile_economia_button = Button(text="Perfil Economia")
        self.domain_input = TextInput(
            text="",
            hint_text="dominio.com",
            multiline=False,
            size_hint=(None, 1),
            width=180,
        )
        self.add_domain_button = Button(text="Adicionar Bloqueio")
        self.monitor_button.bind(on_release=lambda *_args: self.set_view("monitor"))
        self.help_button.bind(on_release=lambda *_args: self.set_view("help"))
        self.privacy_button.bind(on_release=lambda *_args: self.set_view("privacy"))
        self.config_button.bind(on_release=lambda *_args: self.set_view("config"))
        self.save_config_button.bind(on_release=lambda *_args: self.save_config_from_editor())
        self.reload_config_button.bind(on_release=lambda *_args: self.reload_config_in_editor())
        self.open_log_button.bind(on_release=lambda *_args: self.open_access_log())
        self.network_test_button.bind(on_release=lambda *_args: self.run_network_test())
        self.network_test_full_button.bind(on_release=lambda *_args: self.run_network_test_full())
        self.export_report_button.bind(on_release=lambda *_args: self.export_snapshot_report())
        self.profile_normal_button.bind(on_release=lambda *_args: self.apply_profile_preset("normal"))
        self.profile_leve_button.bind(on_release=lambda *_args: self.apply_profile_preset("leve"))
        self.profile_economia_button.bind(on_release=lambda *_args: self.apply_profile_preset("economia_maxima"))
        self.add_domain_button.bind(on_release=lambda *_args: self.add_domain_block_from_input())
        top_actions.add_widget(self.monitor_button)
        top_actions.add_widget(self.help_button)
        top_actions.add_widget(self.privacy_button)
        top_actions.add_widget(self.config_button)
        top_actions.add_widget(self.save_config_button)
        top_actions.add_widget(self.reload_config_button)
        top_actions.add_widget(self.profile_normal_button)
        top_actions.add_widget(self.profile_leve_button)
        top_actions.add_widget(self.profile_economia_button)
        top_actions.add_widget(self.domain_input)
        top_actions.add_widget(self.add_domain_button)
        top_actions.add_widget(self.open_log_button)
        top_actions.add_widget(self.network_test_button)
        top_actions.add_widget(self.network_test_full_button)
        top_actions.add_widget(self.export_report_button)
        self.actions_scroll.add_widget(top_actions)
        self.add_widget(self.actions_scroll)

        # Container dinamico para alternar entre monitor, ajuda e configuracao.
        self.content_container = BoxLayout(size_hint=(1, 1))

        # Painel de monitoramento com rolagem para listas maiores de hosts.
        self.scroll_view = ScrollView(
            size_hint=(1, 1),
            do_scroll_x=False,
            do_scroll_y=True,
            scroll_type=["bars", "content"],
            bar_width=12,
            bar_color=(0.2, 0.6, 0.9, 0.9),
            bar_inactive_color=(0.2, 0.6, 0.9, 0.35),
        )
        self.output_label = Label(
            text="",
            size_hint_y=None,
            halign="left",
            valign="top",
        )
        self.output_label.bind(texture_size=self._update_output_height)
        self.output_label.bind(width=self._sync_output_text)
        self.scroll_view.add_widget(self.output_label)

        # Editor de configuracao em JSON. Fica visivel apenas na aba Config.
        self.config_editor = TextInput(
            text=read_config_text(),
            multiline=True,
            readonly=False,
            font_size=14,
        )

        self.content_container.add_widget(self.scroll_view)
        self.add_widget(self.content_container)

        # Rodape com identidade do projeto e acesso rapido ao GitHub.
        self.footer_container = BoxLayout(
            size_hint=(1, None),
            height=44,
            padding=[8, 4, 8, 4],
            spacing=8,
        )
        current_year = time.strftime("%Y")
        self.footer_label = Label(
            text=(
                f"{APP_NAME} v{APP_VERSION} | "
                f"{APP_AUTHOR} | © {current_year} | Uso local de monitoramento"
            ),
            halign="left",
            valign="middle",
        )
        self.footer_label.bind(size=self._sync_footer_text)
        self.github_button = Button(
            text="GitHub Perfil",
            size_hint=(None, 1),
            width=116,
        )
        self.github_button.bind(on_release=lambda *_args: self.open_project_github())
        self.repos_button = Button(
            text="Outros Projetos",
            size_hint=(None, 1),
            width=122,
        )
        self.repos_button.bind(on_release=lambda *_args: self.open_other_projects())
        self.footer_container.add_widget(self.footer_label)
        self.footer_container.add_widget(self.github_button)
        self.footer_container.add_widget(self.repos_button)
        self.add_widget(self.footer_container)

        self.bind(size=self._apply_responsive_layout)

        # Ajusta o destaque visual do botao selecionado antes da primeira carga.
        self._refresh_view_buttons()
        self._apply_responsive_layout()

        # Ajusta o agendamento do ciclo de acordo com a configuracao atual.
        self._reschedule_monitor_loop()

        # Faz a primeira atualizacao imediatamente para que a tela nao abra vazia.
        self.update_cycle(0)

    def _sync_status_text(self, instance, _value):
        """Ajusta a largura util do texto do status para permitir quebra."""
        instance.text_size = (instance.width - 20, None)

    def _sync_output_text(self, instance, value):
        """Ajusta a largura util do texto principal para layout responsivo."""
        instance.text_size = (value - 20, None)

    def _sync_footer_text(self, instance, _value):
        """Mantem o texto do rodape alinhado e com quebra controlada."""
        instance.text_size = (instance.width - 12, None)

    def _update_output_height(self, instance, value):
        """Expande a altura do rotulo principal conforme o conteudo cresce."""
        instance.height = max(value[1] + 20, self.height)

    def _reschedule_monitor_loop(self):
        """Reagenda o loop de atualizacao quando o intervalo muda."""
        interval = max(1, int(self.monitor_config.get("scan_interval_seconds", 5)))
        if self.loop_event is not None:
            self.loop_event.cancel()
        self.loop_event = Clock.schedule_interval(self.update_cycle, interval)

    def _get_config_mtime(self):
        """Retorna mtime do arquivo de configuracao para detectar mudancas."""
        try:
            return CONFIG_PATH.stat().st_mtime
        except OSError:
            return None

    def refresh_config_if_needed(self, force=False):
        """Recarrega configuracao somente quando necessario."""
        now = time.time()
        check_interval = max(1, int(self.monitor_config.get("config_check_interval_seconds", 3)))
        if not force and (now - self.last_config_check_at) < check_interval:
            return

        self.last_config_check_at = now
        current_mtime = self._get_config_mtime()

        if not force and current_mtime == self.last_config_mtime:
            return

        old_interval = self.monitor_config.get("scan_interval_seconds", 5)
        self.monitor_config = load_config()
        self.last_config_mtime = current_mtime

        if self.monitor_config.get("scan_interval_seconds", 5) != old_interval:
            self._reschedule_monitor_loop()

    def resolve_remote_host_cached(self, ip_address):
        """Resolve host remoto com cache para reduzir custo de DNS reverso."""
        if not self.monitor_config.get("enable_reverse_dns", False):
            return "-"

        now = time.time()
        ttl = max(30, int(self.monitor_config.get("reverse_dns_ttl_seconds", 600)))
        cached = self.reverse_dns_cache.get(ip_address)
        if cached and (now - cached[0]) < ttl:
            return cached[1]

        host = reverse_lookup(ip_address)
        self.reverse_dns_cache[ip_address] = (now, host)
        return host

    def refresh_devices_if_needed(self):
        """Executa scan ARP apenas quando o intervalo de dispositivo expira."""
        now = time.time()
        scan_interval = max(5, int(self.monitor_config.get("device_scan_interval_seconds", 30)))
        auto_mode = "auto" in self.monitor_config.get("scan_networks", ["auto"])
        connected = detect_connected_network_info() if auto_mode else None

        if connected is not None:
            current_signature = f"{connected['local_ip']}|{connected['network_cidr']}"
            if self.last_connected_network != current_signature:
                # Mudou IP/rede da maquina: invalida cache para novo scan imediato.
                self.cached_networks = []
                self.cached_devices = []
                self.cached_scan_errors = []
                self.last_device_scan_at = 0.0
                self.last_connected_network = current_signature

        should_scan = (not self.cached_networks) or ((now - self.last_device_scan_at) >= scan_interval)

        if not should_scan:
            return self.cached_networks, self.cached_devices, self.cached_scan_errors

        networks = resolve_scan_networks(self.monitor_config)
        scanned = []
        scan_errors = []

        use_ping = bool(self.monitor_config.get("enable_ping_fallback", True))
        ping_timeout = max(100, int(self.monitor_config.get("ping_timeout_ms", 300)))
        ping_limit = max(0, int(self.monitor_config.get("ping_sweep_limit", 128)))

        workers = min(4, max(1, len(networks)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    discover_devices_in_network,
                    network,
                    enable_ping_fallback=use_ping,
                    ping_timeout_ms=ping_timeout,
                    ping_sweep_limit=ping_limit,
                ): network
                for network in networks
            }

            for future in concurrent.futures.as_completed(futures):
                devices_list, error_message = future.result()
                scanned.append(devices_list)
                if error_message:
                    scan_errors.append(error_message)

        devices = merge_devices(scanned)
        self.cached_networks = networks
        self.cached_devices = devices
        self.cached_scan_errors = scan_errors
        self.last_device_scan_at = now
        return networks, devices, scan_errors

    def _refresh_view_buttons(self):
        """Reflete na interface qual painel esta ativo no momento."""
        is_monitor = self.current_view == "monitor"
        is_help = self.current_view == "help"
        is_privacy = self.current_view == "privacy"
        is_config = self.current_view == "config"
        self.monitor_button.disabled = is_monitor
        self.help_button.disabled = is_help
        self.privacy_button.disabled = is_privacy
        self.config_button.disabled = is_config
        self.save_config_button.disabled = not is_config
        self.reload_config_button.disabled = not is_config
        self.profile_normal_button.disabled = not is_config
        self.profile_leve_button.disabled = not is_config
        self.profile_economia_button.disabled = not is_config
        self.domain_input.disabled = not is_config
        self.add_domain_button.disabled = not is_config

    def _apply_responsive_layout(self, *_args):
        """Ajusta tamanhos dos controles para telas menores."""
        compact = self.width < 1100
        button_width = 92 if compact else 122
        input_width = 150 if compact else 190

        controls = [
            self.monitor_button,
            self.help_button,
            self.privacy_button,
            self.config_button,
            self.save_config_button,
            self.reload_config_button,
            self.profile_normal_button,
            self.profile_leve_button,
            self.profile_economia_button,
            self.add_domain_button,
            self.open_log_button,
            self.network_test_button,
            self.network_test_full_button,
            self.export_report_button,
        ]

        for control in controls:
            control.size_hint_x = None
            control.width = button_width

        self.domain_input.size_hint_x = None
        self.domain_input.width = input_width
        self.github_button.width = 96 if compact else 116
        self.repos_button.width = 104 if compact else 122

    def open_project_github(self):
        """Abre o perfil/projeto no navegador padrao."""
        try:
            webbrowser.open(APP_GITHUB_URL, new=2)
            self.status_label.text = "GitHub aberto no navegador"
        except Exception as error:
            self.status_label.text = f"Falha ao abrir GitHub: {error}"

    def open_other_projects(self):
        """Abre a pagina de repositorios do perfil no navegador padrao."""
        repos_url = APP_GITHUB_URL.rstrip("/") + "?tab=repositories"
        try:
            webbrowser.open(repos_url, new=2)
            self.status_label.text = "Lista de projetos aberta no navegador"
        except Exception as error:
            self.status_label.text = f"Falha ao abrir lista de projetos: {error}"

    def set_view(self, view_name):
        """Alterna entre monitoramento, ajuda e editor de configuracao."""
        self.current_view = view_name
        self._refresh_view_buttons()

        self.content_container.clear_widgets()

        if view_name == "help":
            self.status_label.text = "Ajuda operacional"
            self.output_label.text = HELP_TEXT
            self.content_container.add_widget(self.scroll_view)
            return

        if view_name == "privacy":
            self.status_label.text = "Painel de privacidade"
            self.refresh_privacy_snapshot(force=True)
            self.output_label.text = "\n".join(self.build_privacy_lines())
            self.content_container.add_widget(self.scroll_view)
            return

        if view_name == "config":
            self.status_label.text = f"Editor de configuracao: {CONFIG_PATH.name}"
            self.reload_config_in_editor(update_status=False)
            self.content_container.add_widget(self.config_editor)
            return

        self.content_container.add_widget(self.scroll_view)
        self.update_cycle(0)

    def refresh_privacy_snapshot(self, force=False):
        """Atualiza cache de privacidade com TTL para evitar chamadas excessivas."""
        now = time.time()
        ttl = max(30, int(self.monitor_config.get("privacy_refresh_seconds", 120)))
        if (not force) and self.privacy_snapshot and (now - self.last_privacy_refresh_at) < ttl:
            return

        connected_network = detect_connected_network_info()
        vpn_interfaces = detect_vpn_interfaces()
        public_ip = fetch_public_ip(timeout=3)
        restricted_targets = bool(self.monitor_config.get("restricted_domains") or self.monitor_config.get("restricted_ips"))

        if restricted_targets and vpn_interfaces:
            tunnel_alert = "Bloqueios locais ativos com tunel VPN detectado."
        elif restricted_targets:
            tunnel_alert = "Bloqueios locais ativos sem tunel VPN detectado."
        elif vpn_interfaces:
            tunnel_alert = "Tunel VPN detectado, mas sem bloqueios configurados."
        else:
            tunnel_alert = "Sem tunel VPN detectado e sem bloqueios configurados."

        self.privacy_snapshot = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "public_ip": public_ip,
            "vpn_interfaces": vpn_interfaces,
            "connected_network": connected_network,
            "tunnel_alert": tunnel_alert,
        }
        self.last_privacy_refresh_at = now

    def build_privacy_lines(self):
        """Monta texto de privacidade para painel dedicado e relatorio."""
        if not self.privacy_snapshot:
            return ["Privacidade: sem dados."]

        connected = self.privacy_snapshot.get("connected_network")
        connected_text = (
            f"Interface: {connected['interface']} | IP local: {connected['local_ip']} | Rede: {connected['network_cidr']}"
            if connected
            else "Interface conectada: indisponivel"
        )

        vpn_interfaces = self.privacy_snapshot.get("vpn_interfaces", [])
        vpn_text = ", ".join(vpn_interfaces) if vpn_interfaces else "Nenhuma"

        return [
            "=== PRIVACIDADE ===",
            f"Atualizado em: {self.privacy_snapshot.get('time', '-')}",
            f"IP publico visivel: {self.privacy_snapshot.get('public_ip', 'Indisponivel')}",
            f"Interfaces VPN ativas: {vpn_text}",
            connected_text,
            f"Alerta de tunel: {self.privacy_snapshot.get('tunnel_alert', '-')}",
        ]

    def open_access_log(self):
        """Abre o arquivo CSV de log no aplicativo padrao do sistema."""
        ensure_access_log_header()
        try:
            if os.name == "nt":
                os.startfile(ACCESS_LOG_PATH)
            elif os.name == "posix":
                subprocess.run(["xdg-open", str(ACCESS_LOG_PATH)], check=False)
            else:
                subprocess.run(["open", str(ACCESS_LOG_PATH)], check=False)
            self.status_label.text = f"Log aberto: {ACCESS_LOG_PATH.name}"
        except OSError as error:
            self.status_label.text = f"Falha ao abrir log: {error}"

    def _compute_network_test_result(self, full_scan=False):
        """Executa diagnostico de conectividade local por ping.

        full_scan=False: usa amostra menor da rede.
        full_scan=True: amplia escopo para mais hosts (com limite de seguranca).
        """
        connected = detect_connected_network_info()
        if not connected:
            return ["Sem interface IPv4 ativa para teste."], "Teste de rede: sem interface ativa"

        timeout_ms = max(100, int(self.monitor_config.get("ping_timeout_ms", 300)))
        sample_size = max(4, int(self.monitor_config.get("network_test_sample_size", 24)))
        full_limit = max(32, int(self.monitor_config.get("network_test_full_max_hosts", 512)))

        gateway = connected.get("gateway")
        gateway_ok = ping_host(gateway, timeout_ms) if gateway else False

        try:
            network = ipaddress.ip_network(connected["network_cidr"], strict=False)
            host_candidates = [str(host) for host in network.hosts()]
        except (ValueError, KeyError):
            host_candidates = []

        local_ip = connected.get("local_ip")
        host_candidates = [item for item in host_candidates if item not in {local_ip, gateway}]

        if full_scan:
            host_candidates = host_candidates[:full_limit]
        else:
            host_candidates = host_candidates[:sample_size]

        reachable_hosts = []
        if host_candidates:
            workers = min(24, max(4, len(host_candidates)))
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(ping_host, ip_addr, timeout_ms): ip_addr
                    for ip_addr in host_candidates
                }
                for future in concurrent.futures.as_completed(futures):
                    ip_addr = futures[future]
                    try:
                        if future.result():
                            reachable_hosts.append(ip_addr)
                    except Exception:
                        continue

        reachable_hosts.sort()
        mode_label = "COMPLETO" if full_scan else "RAPIDO"
        result_lines = [
            f"Modo: {mode_label}",
            f"Interface testada: {connected.get('interface', '-')}",
            f"Rede: {connected.get('network_cidr', '-')}",
            f"Gateway: {gateway or '-'} | {'OK' if gateway_ok else 'SEM RESPOSTA'}",
            f"Hosts testados: {len(host_candidates)} | Respondendo: {len(reachable_hosts)}",
            (
                "Respondendo: " + ", ".join(reachable_hosts[:12])
                if reachable_hosts
                else "Nenhum host respondeu ao ping na amostra."
            ),
        ]

        status_line = f"Teste de rede concluido: {len(reachable_hosts)}/{len(host_candidates)} hosts responderam"
        return result_lines, status_line

    def _run_network_test_async(self, full_scan=False):
        """Executa teste de rede em background para manter a UI responsiva."""
        if self.network_test_running:
            self.status_label.text = "Teste de rede ja esta em execucao"
            return

        self.network_test_running = True
        mode = "completo" if full_scan else "rapido"
        self.status_label.text = f"Executando teste de rede {mode}..."

        def worker():
            try:
                lines, status = self._compute_network_test_result(full_scan=full_scan)
            except Exception as error:
                lines = [f"Falha no teste de rede: {error}"]
                status = "Teste de rede falhou"

            def apply_result(_dt):
                self.last_network_test_lines = lines
                self.status_label.text = status
                self.network_test_running = False
                if self.current_view == "monitor":
                    self.update_cycle(0)

            Clock.schedule_once(apply_result, 0)

        threading.Thread(target=worker, daemon=True).start()

    def run_network_test(self):
        """Executa teste rapido por amostragem."""
        self._run_network_test_async(full_scan=False)

    def run_network_test_full(self):
        """Executa teste completo (faixa maior com limite de seguranca)."""
        self._run_network_test_async(full_scan=True)

    def reload_config_in_editor(self, update_status=True):
        """Recarrega o conteudo do JSON para o editor da aba Config."""
        try:
            self.config_editor.text = read_config_text()
            if update_status:
                self.status_label.text = "Configuracao recarregada do arquivo"
        except OSError as error:
            self.status_label.text = f"Falha ao recarregar configuracao: {error}"

    def save_config_from_editor(self):
        """Valida e salva o texto do editor como monitor_config.json."""
        try:
            save_config_text(self.config_editor.text)
        except json.JSONDecodeError as error:
            self.status_label.text = f"JSON invalido (linha {error.lineno}, coluna {error.colno})"
            return
        except OSError as error:
            self.status_label.text = f"Falha ao salvar configuracao: {error}"
            return

        self.refresh_config_if_needed(force=True)
        self.last_device_scan_at = 0.0
        self.status_label.text = "Configuracao salva com sucesso"

    def apply_profile_preset(self, profile_name):
        """Aplica e salva um preset de desempenho com um clique."""
        profile = PROFILE_PRESETS.get(profile_name)
        if profile is None:
            self.status_label.text = f"Perfil desconhecido: {profile_name}"
            return

        try:
            base_config = json.loads(self.config_editor.text)
        except json.JSONDecodeError:
            base_config = load_config()

        updated_config = DEFAULT_CONFIG.copy()
        updated_config.update(base_config)
        updated_config.update(profile)

        try:
            serialized = json.dumps(updated_config, indent=2, ensure_ascii=False)
            save_config_text(serialized)
            self.config_editor.text = serialized
        except OSError as error:
            self.status_label.text = f"Falha ao aplicar perfil: {error}"
            return

        self.refresh_config_if_needed(force=True)
        self.last_device_scan_at = 0.0
        self.status_label.text = f"Perfil aplicado: {profile_name}"

    def add_domain_block_from_input(self):
        """Adiciona dominio em restricted_domains e salva com um clique."""
        normalized_domain = normalize_domain_input(self.domain_input.text)
        if normalized_domain is None:
            self.status_label.text = "Dominio invalido. Exemplo: site.com"
            return

        try:
            current_config = json.loads(self.config_editor.text)
        except json.JSONDecodeError as error:
            self.status_label.text = f"JSON invalido (linha {error.lineno}, coluna {error.colno})"
            return

        restricted_domains = current_config.get("restricted_domains", [])
        if not isinstance(restricted_domains, list):
            restricted_domains = []

        if normalized_domain in restricted_domains:
            self.status_label.text = f"Dominio ja bloqueado: {normalized_domain}"
            return

        restricted_domains.append(normalized_domain)
        restricted_domains = sorted(set(restricted_domains))
        current_config["restricted_domains"] = restricted_domains

        serialized = json.dumps(current_config, indent=2, ensure_ascii=False)
        try:
            save_config_text(serialized)
        except OSError as error:
            self.status_label.text = f"Falha ao salvar bloqueio: {error}"
            return

        self.config_editor.text = serialized
        self.domain_input.text = ""
        self.refresh_config_if_needed(force=True)
        self.status_label.text = f"Bloqueio adicionado: {normalized_domain}"

    def export_snapshot_report(self):
        """Exporta um snapshot completo do monitor para TXT e CSV."""
        if not self.last_snapshot:
            self.status_label.text = "Nada para exportar ainda. Aguarde um ciclo do monitor."
            return

        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        txt_path = REPORTS_DIR / f"network_snapshot_{timestamp}.txt"
        csv_path = REPORTS_DIR / f"network_snapshot_{timestamp}.csv"

        txt_lines = [
            "=== SNAPSHOT DO MONITOR ===",
            f"Gerado em: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "=== REDES MONITORADAS ===",
            ", ".join(self.last_snapshot["networks"]) if self.last_snapshot["networks"] else "Nenhuma rede detectada.",
            "",
            "=== INFRAESTRUTURA ===",
            *self.last_snapshot["infrastructure_lines"],
            "",
            f"=== DISPOSITIVOS DETECTADOS ({len(self.last_snapshot['devices'])}) ===",
        ]

        if self.last_snapshot["devices"]:
            txt_lines.extend(
                (
                    f"{device['ip']} | {device['mac']} | {device.get('discovery', 'DESCONHECIDO')} | "
                    f"{self.last_snapshot['device_connection_summary'].get(device['ip'], 'Sem dados')}"
                )
                for device in self.last_snapshot["devices"]
            )
        else:
            txt_lines.append("Nenhum dispositivo encontrado.")

        txt_lines.extend([
            "",
            f"=== ACESSOS ATIVOS ({len(self.last_snapshot['connections'])}) ===",
        ])

        if self.last_snapshot["connections"]:
            txt_lines.extend(
                f"{item['process']} | {item['protocol']} | {item['local']} -> {item['remote']} | {item['remote_host']} | {item['status']}"
                for item in self.last_snapshot["connections"]
            )
        else:
            txt_lines.append("Nenhuma conexao relevante capturada.")

        if self.last_snapshot["scan_errors"]:
            txt_lines.extend(["", "=== ALERTAS ===", *self.last_snapshot["scan_errors"]])

        txt_path.write_text("\n".join(txt_lines), encoding="utf-8")

        with csv_path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["section", "field_1", "field_2", "field_3", "field_4", "field_5", "field_6"])

            for network in self.last_snapshot["networks"]:
                writer.writerow(["network", network, "", "", "", "", ""])

            for line in self.last_snapshot["infrastructure_lines"]:
                writer.writerow(["infrastructure", line, "", "", "", "", ""])

            for device in self.last_snapshot["devices"]:
                writer.writerow([
                    "device",
                    device["ip"],
                    device["mac"],
                    device.get("discovery", "DESCONHECIDO"),
                    self.last_snapshot["device_connection_summary"].get(device["ip"], "Sem dados"),
                    "",
                    "",
                ])

            for item in self.last_snapshot["connections"]:
                writer.writerow([
                    "connection",
                    item["process"],
                    item["protocol"],
                    item["local"],
                    item["remote"],
                    item["remote_host"],
                    item["status"],
                ])

            for alert in self.last_snapshot["scan_errors"]:
                writer.writerow(["alert", alert, "", "", "", "", ""])

        self.status_label.text = f"Relatorio exportado: {txt_path.name} e {csv_path.name}"

    def refresh_restrictions(self):
        """Reaplica bloqueios apenas quando a configuracao muda ou expira.

        O intervalo de 5 minutos reduz chamadas repetitivas ao netsh sem perder a
        capacidade de convergir o estado quando o arquivo JSON for alterado.
        """
        restriction_signature = json.dumps(
            {
                "restricted_domains": self.monitor_config.get("restricted_domains", []),
                "restricted_ips": self.monitor_config.get("restricted_ips", []),
            },
            sort_keys=True,
        )

        should_refresh = (
            restriction_signature != self.last_restriction_signature
            or time.time() - self.last_restriction_refresh > 300
        )
        if not should_refresh:
            return

        self.restriction_messages, _ = apply_restrictions(self.monitor_config)
        self.last_restriction_signature = restriction_signature
        self.last_restriction_refresh = time.time()

    def update_cycle(self, _dt):
        """Executa um ciclo completo de atualizacao do monitor.

        Cada ciclo recarrega a configuracao, aplica restricoes quando necessario,
        escaneia redes, coleta conexoes ativas, grava o log e atualiza a UI.
        """
        if self.current_view != "monitor":
            return

        try:
            self.refresh_config_if_needed()
            self.refresh_restrictions()
            self.refresh_privacy_snapshot()

            networks, devices, scan_errors = self.refresh_devices_if_needed()
            connections = get_active_connections(
                self.monitor_config["connection_display_limit"],
                self.resolve_remote_host_cached,
            )
            log_new_connections(self.connection_cache, connections)
            infrastructure_lines = summarize_infrastructure(devices, self.monitor_config)
            connected_network = detect_connected_network_info()
            device_connection_summary = build_device_connection_summary(devices, connections)

            self.last_snapshot = {
                "networks": networks,
                "infrastructure_lines": infrastructure_lines,
                "devices": devices,
                "device_connection_summary": device_connection_summary,
                "connections": connections,
                "scan_errors": scan_errors,
            }

            report_lines = [
                "=== REDE CONECTADA ===",
                (
                    f"Interface: {connected_network['interface']} | IP local: {connected_network['local_ip']} | "
                    f"Rede: {connected_network['network_cidr']} | Gateway: {connected_network.get('gateway') or '-'}"
                )
                if connected_network
                else "Nenhuma interface IPv4 ativa detectada.",
                "",
                "=== REDES MONITORADAS ===",
                ", ".join(networks) if networks else "Nenhuma rede local detectada.",
                "",
                "=== INFRAESTRUTURA ===",
                *infrastructure_lines,
                "",
                *self.build_privacy_lines(),
                "",
                "=== TESTE DE REDE ===",
                *self.last_network_test_lines,
                "",
                f"=== DISPOSITIVOS DETECTADOS ({len(devices)}) ===",
            ]

            if devices:
                report_lines.extend(
                    (
                        f"{device['ip']} | {device['mac']} | {device.get('discovery', 'DESCONHECIDO')} | "
                        f"{device_connection_summary.get(device['ip'], 'Sem dados')}"
                    )
                    for device in devices
                )
            else:
                report_lines.append("Nenhum dispositivo encontrado no scan ARP.")

            report_lines.extend([
                "",
                f"=== ACESSOS ATIVOS ({len(connections)}) ===",
            ])

            if connections:
                report_lines.extend(
                    f"{item['process']} | {item['protocol']} | {item['local']} -> {item['remote']} | {item['remote_host']} | {item['status']}"
                    for item in connections
                )
            else:
                report_lines.append("Nenhuma conexao relevante capturada no momento.")

            if scan_errors:
                report_lines.extend(["", "=== ALERTAS ===", *scan_errors])

            report_lines.extend([
                "",
                f"Log de acessos: {ACCESS_LOG_PATH.name}",
                f"Configuracao ativa: {CONFIG_PATH.name}",
                f"Versao do app: {APP_NAME} v{APP_VERSION}",
                "Use a aba Config para editar e salvar sem sair do app",
            ])

            self.status_label.text = " | ".join(self.restriction_messages[:2])
            self.output_label.text = "\n".join(report_lines)
        except Exception as error:
            self.status_label.text = "Monitor com erro"
            self.output_label.text = f"Erro geral: {error}"


class MyApp(App):
    """Ponto de entrada da aplicacao Kivy."""

    def build(self):
        return MonitorApp()


if __name__ == "__main__":
    MyApp().run()
