# Monitor de Rede Corporativa Local

## Visao geral

Este projeto e um aplicativo desktop em Python com Kivy para monitoramento local de rede.

Ele foi pensado para uso operacional em uma estacao Windows e entrega quatro funcoes principais:

- descoberta de dispositivos na rede local por ARP
- monitoramento de conexoes ativas da propria maquina
- registro de acessos observados em arquivo CSV
- aplicacao opcional de bloqueios locais via Windows Firewall

A interface agora possui quatro visoes e controles rapidos:

- `Monitor`: relatorio operacional em tempo real
- `Ajuda`: resumo embutido de funcionamento e limitacoes
- `Privacidade`: painel com IP publico, interfaces VPN e alerta de tunel
- `Config`: editor do `monitor_config.json` dentro do app
- `Perfil Normal`, `Perfil Leve`, `Perfil Economia`: troca de preset com um clique na aba Config
- `Abrir Log`: abre `access_log.csv` no programa padrao do sistema
- `Exportar Relatorio`: gera snapshot completo em TXT e CSV
- `Rodape`: assinatura padronizada com versao, autor, ano e atalhos para GitHub/Saiba mais

O projeto nao substitui firewall corporativo, proxy, filtro DNS centralizado, NAC ou SIEM. Ele funciona como ferramenta local de observacao e controle no host onde esta sendo executado.

## Arquivos principais

- [main.py](main.py): logica do aplicativo, interface, varredura, monitoramento e bloqueios
- [monitor_config.json](monitor_config.json): parametros operacionais do monitor
- [monitor_config.example.jsonc](monitor_config.example.jsonc): exemplo comentado da configuracao
- [requirements.txt](requirements.txt): dependencias Python do projeto
- `access_log.csv`: log gerado em tempo de execucao com novas conexoes observadas

## Como o aplicativo funciona

### 1. Descoberta de redes

O aplicativo le as interfaces IPv4 locais usando `psutil.net_if_addrs()`.

Com base em IP e mascara de rede de cada interface, ele calcula as sub-redes locais usando `ipaddress.IPv4Interface`.

Se `scan_networks` estiver com o valor `auto`, o programa usa essas redes detectadas automaticamente.

Tambem e possivel adicionar redes extras manualmente no arquivo de configuracao.

O proprio aplicativo agora possui uma tela `Ajuda`, acessivel por botao na interface, para consulta rapida durante a operacao.

Tambem existe uma tela `Config` para editar e salvar o JSON sem sair do aplicativo.

### 2. Descoberta de dispositivos

Para cada rede a ser monitorada, o sistema executa broadcast ARP com Scapy.

Cada resposta ARP gera um registro com:

- IP do dispositivo
- endereco MAC do dispositivo

Os resultados sao consolidados em uma lista unica para exibicao na interface.

### 3. Monitoramento de modem e repetidor

O arquivo `monitor_config.json` tem uma secao chamada `infrastructure_devices`.

Ali voce informa os equipamentos que deseja acompanhar, por exemplo:

```json
"infrastructure_devices": [
  { "name": "Modem", "ip": "192.168.1.1" },
  { "name": "Repetidor", "ip": "192.168.1.2" }
]
```

Se esses IPs responderem no scan da rede, o app marca o equipamento como online e mostra o MAC detectado.

Se nao responderem, o app informa que o dispositivo esta offline ou fora da sub-rede monitorada.

### 4. Monitoramento de acessos

O aplicativo usa `psutil.net_connections(kind="inet")` para listar conexoes IPv4 e IPv6 da maquina local.

Ele filtra os estados mais uteis para observacao operacional, como:

- `ESTABLISHED`
- `SYN_SENT`
- `CLOSE_WAIT`

Para cada conexao ele tenta mostrar:

- processo responsavel
- protocolo TCP ou UDP
- IP e porta local
- IP e porta remota
- nome reverso do IP remoto, quando disponivel
- estado da conexao

Essas informacoes aparecem na interface e novas conexoes sao gravadas em `access_log.csv`.

## Como funcionam os bloqueios

Os bloqueios sao locais e usam `netsh advfirewall firewall` no Windows.

Ha dois tipos de alvo:

### Bloqueio por IP

Voce preenche a lista `restricted_ips` no JSON:

```json
"restricted_ips": [
  "8.8.8.8",
  "1.1.1.1"
]
```

O aplicativo cria uma regra de saida no Windows Firewall para bloquear esses IPs remotos.

### Bloqueio por dominio

Voce preenche a lista `restricted_domains`:

```json
"restricted_domains": [
  "facebook.com",
  "tiktok.com"
]
```

O aplicativo resolve o dominio para IPs e cria regras de bloqueio para os IPs encontrados.

### Limitacoes do bloqueio por dominio

Esse metodo e util, mas tem limitacoes tecnicas:

- dominios com CDN podem mudar de IP com frequencia
- um dominio pode resolver para multiplos IPs
- HTTPS nao e inspecionado
- o bloqueio vale apenas para a maquina onde o app esta rodando
- para aplicar as regras, o app precisa ser executado como Administrador

Para controle corporativo real em toda a rede, o ideal e usar firewall/UTM, proxy e filtragem DNS centralizada.

## Configuracao

Exemplo completo de `monitor_config.json`:

```json
{
  "scan_interval_seconds": 5,
  "scan_networks": [
    "auto",
    "192.168.0.0/24",
    "192.168.1.0/24"
  ],
  "infrastructure_devices": [
    {
      "name": "Modem",
      "ip": "192.168.0.1"
    },
    {
      "name": "Repetidor",
      "ip": "192.168.0.2"
    }
  ],
  "restricted_domains": [
    "facebook.com",
    "tiktok.com"
  ],
  "restricted_ips": [
    "8.8.8.8"
  ],
  "connection_display_limit": 20
}
```

### Significado dos campos

- `scan_interval_seconds`: intervalo entre ciclos do monitor
- `scan_networks`: redes a escanear; `auto` usa deteccao automatica
- `infrastructure_devices`: equipamentos de infraestrutura acompanhados por nome e IP
- `restricted_domains`: dominios que o app tentara bloquear localmente
- `restricted_ips`: IPs remotos bloqueados localmente
- `connection_display_limit`: quantidade maxima de conexoes mostradas na interface
- `device_scan_interval_seconds`: intervalo da varredura ARP de dispositivos
- `config_check_interval_seconds`: frequencia de verificacao de mudanca no arquivo de configuracao
- `enable_reverse_dns`: ativa/desativa resolucao reversa de host remoto
- `reverse_dns_ttl_seconds`: tempo de cache de DNS reverso

Se quiser um arquivo com explicacoes inline, use [monitor_config.example.jsonc](monitor_config.example.jsonc) como referencia. O app continua lendo apenas [monitor_config.json](monitor_config.json), porque JSON puro nao aceita comentarios.

## Requisitos operacionais

- Windows para uso da funcionalidade de bloqueio por firewall
- permissoes administrativas para aplicar regras de bloqueio
- mesma sub-rede de camada 2 para descoberta ARP de dispositivos
- Python e dependencias instaladas na `.venv`

## Como executar

### Opcao 1: com a venv ativada

```powershell
.\.venv\Scripts\Activate.ps1
python main.py
```

### Opcao 2: usando o Python da venv diretamente

```powershell
.\.venv\Scripts\python.exe main.py
```

### Para permitir bloqueios

Abra o PowerShell como Administrador antes de executar o app.

## Distribuicao para outros dispositivos

Executavel e pacote zip sao gerados na pasta `release`:

- `release/dist/MonitorRede.exe`
- `release/MonitorRede-win64-YYYYMMDD-HHMM.zip`

Para distribuir, basta copiar o arquivo ZIP para o dispositivo destino, extrair e executar o `.exe`.

Observacao: para aplicar regras de firewall no destino, execute o app como Administrador.

### Para abrir a ajuda dentro do app

Depois que a janela abrir, clique no botao `Ajuda` para alternar da visao operacional para a documentacao resumida embutida na interface.

### Para editar configuracao dentro do app

1. Clique em `Config`.
2. Edite o JSON no painel.
3. Clique em `Salvar Config`.
4. Se precisar descartar alteracoes locais, clique em `Recarregar Config`.

Se o JSON estiver invalido, o app mostra a linha e coluna do erro na barra de status.

### Para trocar perfil de desempenho com um clique

1. Clique em `Config`.
2. Clique em `Perfil Normal`, `Perfil Leve` ou `Perfil Economia`.

O app aplica o preset e salva automaticamente no `monitor_config.json`.

### Para abrir o CSV de acessos

Clique em `Abrir Log` na barra superior.

### Para exportar um snapshot completo

Clique em `Exportar Relatorio` na barra superior.

O app gera dois arquivos na pasta `reports`:

- `network_snapshot_YYYYMMDD_HHMMSS.txt`
- `network_snapshot_YYYYMMDD_HHMMSS.csv`

O snapshot inclui:

- redes monitoradas
- infraestrutura (modem/repetidor/gateway)
- dispositivos detectados
- conexoes ativas visiveis no ciclo
- alertas de varredura

## Limitacoes do projeto

- o monitoramento de acessos e da maquina local, nao de toda a rede
- o scan ARP nao atravessa roteadores
- repetidores em bridge podem nao aparecer como equipamento gerenciavel
- o bloqueio por dominio depende de resolucao DNS para IPs
- aplicacoes com proxy, VPN ou DNS proprio podem reduzir a efetividade do bloqueio local

## Cenario corporativo recomendado

Use este projeto como complemento local para observacao e testes.

Para ambiente corporativo de producao, o desenho recomendado e:

- firewall/UTM com politicas por grupo ou VLAN
- DNS corporativo com listas de bloqueio
- proxy seguro para navegacao web
- GPO, MDM ou Intune para forcar DNS e politicas de endpoint
- inventario centralizado e logs em SIEM

## Resumo tecnico do fluxo

1. O app carrega `monitor_config.json`.
2. Descobre as redes locais ou usa as redes informadas.
3. Varre cada rede com ARP usando Scapy.
4. Consolida os dispositivos encontrados.
5. Verifica modem, repetidor e gateways configurados.
6. Coleta conexoes ativas da maquina local com Psutil.
7. Registra novas conexoes em `access_log.csv`.
8. Aplica ou reaplica bloqueios locais quando necessario.
9. Atualiza a interface Kivy com o resumo atual.
