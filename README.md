# ZoneStrike

Recon + TCP Port Scan + Reporting (JSON/CSV/HTML) em modo **interativo** e com **saída em tempo real**.

> **Uso permitido apenas com autorização explícita.**
> ZoneStrike é uma ferramenta educacional para ambientes controlados/labs e testes autorizados.

---

## Recursos

* **Modo interativo**: execute `python3 zonestrike.py` e responda às perguntas.
* **Discovery (Recon)**

  * **Passivo**: consultas DNS leves (NS/MX/TXT + apex)
  * **Seeds embutidas**: uma lista pequena de subdomínios comuns (ex.: `www`, `dev`, `api`, etc.)
  * **Wordlist opcional**: arquivo **no mesmo diretório** do `zonestrike.py`
* **Port Scan TCP** (Top N portas) com base em `nmap-services`
* **Enrichment**

  * Banner grab (best-effort)
  * HTTP probe (HEAD/GET) para status, server header e title (best-effort)
* **Relatórios**

  * `report.json`
  * `report.csv`
  * HTML rico em `reports/` com `*_index.html` + páginas por host
* **Live output**: acompanha discovery, scan e enrich no terminal em tempo real

---

## Requisitos

* Python **3.10+** (recomendado)
* Linux (Kali/Ubuntu etc.)
* `nmap-services` disponível (instalando o `nmap`)

### Dependências Python

* `dnspython`

Arquivo `requirements.txt`:

```txt
dnspython>=2.6.0
```

---

## Instalação

```bash
git clone https://github.com/taissocout/zonestrike.git
cd zonestrike

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

# (recomendado) para garantir nmap-services
sudo apt update && sudo apt install -y nmap
```

---

## Uso (Interativo)

Execute:

```bash
python3 zonestrike.py
```

O ZoneStrike vai pedir:

1. **Target/domain** (ex.: `businesscorp.com.br`, `lab.local`)
2. **Top N ports** (ex.: `100`, `300`, `1000`)
3. **Nome do report** (ex.: `lab_report`)
4. **Wordlist** (opcional) — deve estar no **mesmo diretório** do `zonestrike.py`

Ao terminar, ele vai gerar:

* `lab_report.json`
* `lab_report.csv`
* `reports/lab_report_index.html` (e páginas por host)

E vai imprimir o link:

* `file:///.../reports/lab_report_index.html`

*(Ele também tenta abrir automaticamente no navegador.)*

---

## Wordlist (Opcional)

A wordlist **deve ficar no mesmo diretório** do script:

```
zonestrike.py
minha_wordlist.txt
requirements.txt
```

Exemplo:

```bash
nano minha_wordlist.txt
```

Você pode inserir:

* labels (`dev`, `api`, `mail`) → viram `dev.<target>`
* ou FQDNs completos (`dev.lab.local`) → usados como estão

Depois, ao rodar o ZoneStrike, informe o arquivo quando ele perguntar.

---

## Saída em tempo real (Live)

Durante a execução, você verá:

* **Discovery** em tempo real:
  `fqdn -> IPs`
* **Scan** em tempo real:

  * `[SCAN] (x/y) host -> ip`
  * `[OPEN] host ip:porta/tcp` assim que encontrar
  * `[..] progress a/b` como “heartbeat”
  * `[DONE] ... open_ports=N`
* **Enrich** em tempo real:

  * `[ENRICH] host ip:porta -> service HTTP:status`

---

## Estrutura de arquivos gerados

Exemplo após um run:

```
lab_report.json
lab_report.csv
reports/
  lab_report_index.html
  lab_report_dev.lab.local_10.0.0.10.html
  lab_report_mail.lab.local_10.0.0.20.html
```

---

## Dicas de uso em laboratório

* Prefira targets **do seu lab** (VMs, DNS interno, ambientes autorizados).
* Comece com `Top N ports = 100` para um resultado rápido.
* Aumente para `300` ou `1000` quando quiser mais cobertura.
* Evite valores muito altos se sua máquina/ambiente for pequeno.

---

## Segurança / Legal

* Use **somente** com autorização explícita e por escrito (quando aplicável).
* Você é responsável pelo uso e impactos no ambiente.
* Em caso de dúvida, valide o escopo e limites do teste antes de executar.

---

## Créditos

* **Autor:** Taisso Cout
* **LinkedIn:** https://www.linkedin.com/in/taissocout_cybersecurity
* **GitHub:** https://github.com/taissocout/zonestrike


