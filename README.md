# Scantrely — External Attack Surface Management

> Monitoramento contínuo de superfície de ataque externa com +40 ferramentas nativas. Subdomínios, portas, tecnologias, vulnerabilidades, secrets, cloud — tudo em um pipeline automatizado.

![Pipeline](https://img.shields.io/badge/pipeline-14%20fases-blue)
![Módulos](https://img.shields.io/badge/módulos-79-green)
![Python](https://img.shields.io/badge/python-3.10+-yellow)
![Playwright](https://img.shields.io/badge/playwright-headless-purple)

---

## Funcionalidades

- **Descoberta passiva** — 20 fontes de subdomínios (subfinder, amass, assetfinder, crt.sh, theHarvester, GitHub, APIs)
- **Intel & OSINT** — Shodan, HIBP/Dehashed breach data, CertStream, Postman, APK recon, container registry scan
- **Validação DNS** — brute-force de subdomínios, zone transfer, DNSSEC
- **Perfil do alvo** — WAF detection, Wappalyzer, headers de segurança, fingerprint de vendor, banner grab TCP
- **JavaScript recon** — descoberta de JS (katana), extração de endpoints (LinkFinder), secrets (35 patterns + source maps)
- **Crawling** — Wayback URLs, Playwright headless spider, gowitness screenshots, API discovery
- **Port scan** — 54 portas TCP (naabu/nmap/masscan) + 25 UDP
- **Serviços & CMS** — banner grabbing, WordPress/Drupal scan, MySQL/PostgreSQL/MSSQL/Oracle probes
- **Vuln scan** — subdomain takeover, CVE lookup (NVD), CORS, infra exposure, default creds, GraphQL, SNMP, SMTP
- **Nuclei** — template-based vulnerability scanner (API panels, tokens, exposures)
- **Browser recon** — Playwright headless deep scan: JS analysis, secrets, CSP, CORS, forms, IDOR/XSS

---

## Arquitetura

```
server.py (Flask)
  ├── routes/          API REST
  ├── core/
  │   ├── pipeline.py   ReconRunner — motor de execução (14 fases, 79 módulos)
  │   ├── recon.py      49 funções standalone de recon
  │   ├── database.py   SQLite com WAL mode
  │   └── jobs.py       JobScheduler — fila FIFO de jobs
  ├── utils/
  │   ├── tools.py       24 ferramentas registradas (CLI + API)
  │   ├── tool_gate.py   Controle de concorrência por ferramenta
  │   ├── command_runner.py  Subprocess executor com timeout
  │   └── dep_confusion.py   Dependency confusion (npm/PyPI/RubyGems/NuGet/Packagist/Cargo/Hex)
  ├── playwright_agent/  Recon baseado em browser (Chromium headless)
  ├── bin/              34 binários (Go, Python)
  └── static/           Frontend SPA (vanilla JS + CSS)
```

---

## Perfis de Execução

| Perfil | Uso | Fases | Limite |
|--------|-----|-------|--------|
| `passive_bulk` | Varredura de milhares de domínios | Fase 1 | Seguro para fila grande |
| `full` | Pipeline completa | Todas as 14 fases | ~3-4h por domínio |
| `active_light` | Validação de hosts vivos | Fases 4-6 | Máx 25 hosts |
| `active_heavy` | Testes pesados | Fases 7-10 | Máx 5 hosts |

---

## Instalação Rápida

```bash
# Clone
git clone https://github.com/seu-user/scantrely.git
cd scantrely

# Instalar dependências de sistema (Debian/Ubuntu)
sudo apt install -y nmap masscan chromium libnss3 libatk-bridge2.0-0 libgbm1 libasound2

# Instalar Python deps
pip install -r requirements.txt

# Instalar ferramentas externas (subfinder, amass, nuclei, etc.)
bash install_tools.sh

# Instalar Playwright (browser recon)
playwright install chromium

# Iniciar servidor
bash restart_server.sh
```

Acesse `http://localhost:5000` — login padrão: `admin` / `admin`

---

## Variáveis de Ambiente

| Variável | Padrão | Descrição |
|----------|--------|-----------|
| `ASM_JOB_WORKERS` | 1 | Jobs simultâneos |
| `ASM_GLOBAL_PROC_LIMIT` | 6 | Subprocessos máximo |
| `ASM_DOMAIN_FANOUT_WORKERS` | 3 | Domínios em paralelo por módulo |
| `ASM_GATE_DEFAULT` | 3 | Concorrência por ferramenta |
| `ASM_WATCHDOG_MAX_LOAD` | 4 | Pausa fila se load > N |
| `ASM_WATCHDOG_MIN_MEM_MB` | 1536 | Pausa fila se RAM < N MB |
| `ASM_WATCHDOG_MAX_RECON_PROCS` | 10 | Pausa fila se processos > N |

---

## API

```bash
# Iniciar scan
curl -X POST http://localhost:5000/api/recon/empresa/pipeline \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: $TOKEN" \
  -d '{"profile":"full","mode":"balanced"}'

# Status do pipeline
curl http://localhost:5000/api/recon/empresa/pipeline \
  -H "X-Auth-Token: $TOKEN"

# Listar screenshots
curl http://localhost:5000/api/screenshots/empresa \
  -H "X-Auth-Token: $TOKEN"

# Clear data
curl -X DELETE http://localhost:5000/api/recon/empresa/data \
  -H "X-Auth-Token: $TOKEN"
```

---

## Segurança

- **Timeout global**: todo subprocesso tem timeout padrão de 300s
- **SQLite busy_timeout**: 5000ms — elimina retry storms
- **Watchdog**: monitora load, RAM e processos — pausa fila automaticamente
- **ToolGate**: limite por ferramenta (nuclei=1, naabu=1, httpx=3, etc)
- **Rate limiting**: por fase, por domínio, com jitter e backoff

---

## Licença

MIT

