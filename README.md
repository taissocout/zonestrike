````markdown
# ZoneStrike 🔥  
**AXFR Discovery + TCP Port Scan + Rich Reporting (JSON/CSV/HTML) + Interactive Mode**

> **ZoneStrike** é uma ferramenta focada em **descoberta de hosts via AXFR (quando permitido)** e **varredura TCP de portas** com geração de relatórios **ricos e clicáveis** (HTML) — ideal para **laboratórios**, **ambientes controlados** e **pentests autorizados**.

⚠️ **Uso permitido somente com autorização explícita.**  
O autor não se responsabiliza por uso indevido.

---

## ✨ Features

✅ **AXFR (Zone Transfer)** para enumerar subdomínios/hosts quando o nameserver permite  
✅ Resolve **FQDN → IP** com fallback inteligente (NS → resolver do sistema)  
✅ **Varredura TCP** em **Top N portas** (com base no `nmap-services`)  
✅ **Escaneia primeiro → enriquece depois** (otimiza tempo e reduz ruído)  
✅ Enriquecimento opcional:  
- **Banner grabbing** (quando disponível)  
- **HTTP probe** (status, server header e `<title>`) em portas web comuns  
✅ Relatórios:
- **JSON** (completo e estruturado)
- **CSV** (para grep, Excel, pandas)
- **HTML** (**Index + relatório por host**, com links e “Service Matrix”)  
✅ Modo **interativo** (`--interactive`) para você só digitar **domínio**, **Top N** e **nome do report**  
✅ **Auto-open** do relatório HTML no browser

---

## 📸 Preview do Report (HTML)

O HTML gera:
- **Dashboard** com métricas do scan
- **Top Ports / Top Services**
- **Most Exposed Hosts**
- **Service Matrix (Host → Porta/Serviço/Produto/Versão)**
- Links para **relatório detalhado por host**

---

## ⚙️ Requisitos

- Python **3.10+** (recomendado)
- `dnspython`
- `nmap-services` (vem com o `nmap`)

### Instalar dependências no Kali/Debian:
```bash
sudo apt update
sudo apt install -y python3 python3-venv nmap
````

---

## 🚀 Instalação

### 1) Clone o repositório

```bash
git clone https://github.com/taissocout/zonestrike.git
cd zonestrike
```

### 2) Crie o ambiente virtual e instale dependências

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

> Se você ainda não tiver o `requirements.txt`, crie com:

```bash
echo "dnspython>=2.6.0" > requirements.txt
```

---

## ✅ Uso rápido (modo interativo)

O modo interativo é o recomendado para o fluxo do dia a dia:

```bash
python3 zonestrike.py --interactive
```

Ele pergunta:

* **Domínio**
* **Top N portas** (ex.: 100, 300, 1000)
* **Nome do report**
* Se você quer: **enrich**, **http-probe**, **html**, **auto-open**

No final ele:

* cria `.json` e `.csv`
* gera HTML em `./reports`
* imprime um link `file://...` clicável
* abre automaticamente o relatório (se selecionado)

---

## 🧪 Uso via comando (sem wizard)

### Exemplo: Top 100 portas + enrich + HTML + abrir relatório

```bash
python3 zonestrike.py --domain businesscorp.com.br --top 100 \
  --enrich --http-probe --html --open \
  --out report --html-dir reports
```

### Exemplo: Top 1000 portas (default) e só JSON/CSV

```bash
python3 zonestrike.py --domain businesscorp.com.br --top 1000 --out scan1
```

### Exemplo: listar hosts resolvidos antes de escanear

```bash
python3 zonestrike.py --domain businesscorp.com.br --top 100 \
  --list-hosts --out lab --html --open
```

---

## 🧩 Flags principais

| Flag                 | Descrição                                           |
| -------------------- | --------------------------------------------------- |
| `--interactive`      | Wizard interativo (domínio, topN, report name)      |
| `--domain`           | Domínio/zona alvo (ex.: `example.com`)              |
| `--ns`               | Nameserver (IP ou hostname) opcional                |
| `--top`              | Top N portas (ordem do `nmap-services`)             |
| `--enrich`           | Enriquecimento (banner, heurísticas de serviço)     |
| `--http-probe`       | HTTP status/server/title em portas web comuns       |
| `--html`             | Gera HTML (Index + per-host)                        |
| `--html-dir`         | Pasta do HTML (default: `reports`)                  |
| `--open`             | Abre automaticamente o HTML no browser              |
| `--out`              | Nome base do report (gera `.json`, `.csv`, `.html`) |
| `--host-concurrency` | Hosts paralelos (default: 10)                       |
| `--port-concurrency` | Portas paralelas por host (default: 200)            |
| `--timeout`          | Timeout TCP (default: 1.2s)                         |

---

## 📦 Saídas geradas

Se `--out report`:

* `report.json` → relatório completo (estruturado)
* `report.csv` → export para grep/Excel/pandas
* `reports/report_index.html` → dashboard do scan (clicável)
* `reports/report_<host>.html` → detalhado por host

> O **Index** agrega por hostname e mostra **Service Matrix** com:
> `host → portas/serviços → produto/versão (quando houver evidência)`

---

## 🔎 Dicas para análise rápida

### Grep por portas específicas:

```bash
grep ",22,tcp,open" report.csv
```

### Filtrar por serviço:

```bash
grep ",http," report.csv
```

### Ver só hosts com mais exposição:

```bash
cut -d, -f1,3,6 report.csv | sort | uniq -c | sort -nr | head
```

---

## 🛡️ Boas práticas e segurança (IMPORTANTE)

* Execute **somente em ambientes autorizados** (labs / clientes com permissão).
* Comece com `--top 100` e vá aumentando conforme necessidade.
* Use `--timeout` e `--port-concurrency` moderados para não causar overload.
* Em ambientes reais: registre autorização, escopo, e janela de teste.

---

## 🧠 Roadmap (próximas versões)

* [ ] Exportar relatório **Markdown** para anexar em relatório técnico
* [ ] “Risk notes” por porta (ex.: exposição típica, recomendações defensivas)
* [ ] Cache de resolução DNS (reduz tempo)
* [ ] Templates HTML alternativos (dark/light + print-friendly)
* [ ] “Diff mode” (comparar scans e mostrar mudanças)

---

## 👤 Credits

**Autor:** Cout

* LinkedIn: [https://www.linkedin.com/in/SEU_LINKEDIN](https://www.linkedin.com/in/SEU_LINKEDIN)
* GitHub: [https://github.com/taissocout/zonestrike](https://github.com/taissocout/zonestrike)

---

## 📄 License

Escolha uma licença para o projeto (ex.: MIT).
Se quiser, eu já te mando o `LICENSE` pronto e adiciono badge no README.

```
::contentReference[oaicite:0]{index=0}
```

