# Event Viewer CLI

Programa em Python para **monitorar eventos do Active Directory** (criação/exclusão de usuários e grupos, logons, bloqueios de conta, alterações de objetos e de política de domínio — ver [CLAUDE.md](CLAUDE.md)) a partir do **Windows Event Viewer**. Também funciona como leitor genérico de qualquer log (Application, System, etc.), com filtros por ID, nível, origem, usuário, data ou palavra-chave, exportação para console, CSV ou JSON, e acompanhamento em tempo real (modo `--watch`).

## Requisitos

- Windows
- Python 3.8+
- Pacote `pywin32`

## Instalação

```powershell
pip install -r requirements.txt
```

> Para consultar o log **Security**, normalmente é necessário executar o terminal/PowerShell **como Administrador**, pois esse log exige privilégios elevados.

## Uso básico

Monitorar eventos do Active Directory (modo dedicado, ver seção abaixo):

```powershell
python main.py --ad --limit 10
```

Ler qualquer outro log (ex: Application, últimos 10 eventos):

```powershell
python main.py --log Application --limit 10
```

## Monitoramento do Active Directory

Para acompanhar ações administrativas do AD (criação/exclusão de usuários e
grupos, logons, bloqueios de conta, alterações de objetos e política de
domínio), use o modo `--ad`. Ele aplica automaticamente `--log Security` e os
Event IDs listados em [CLAUDE.md](CLAUDE.md):

```powershell
python main.py --ad --limit 200 --output csv --outfile ad_events.csv
python main.py --ad --watch
```

Cada evento retornado nesse modo inclui o campo `action` com a ação
correspondente (ex: "Usuario criado", "Conta bloqueada"). É possível
sobrepor `--log` ou `--event-id` manualmente para restringir ainda mais:

```powershell
python main.py --ad --user "joao.silva"
python main.py --ad --event-id 4625,4740,4767   # so falhas de logon e bloqueios/desbloqueios
```

Ver a tabela de IDs suportados a qualquer momento:

```powershell
python main.py --list-ad-ids
```

## Listar logs disponíveis

```powershell
python main.py --list-logs
```

Lista todos os canais/logs de evento disponíveis no computador (ex: `Application`, `System`, `Security`, `Setup`, e diversos logs específicos de aplicativos/serviços).

## Opções (filtros)

| Opção | Descrição | Exemplo |
|---|---|---|
| `--ad` | Modo Active Directory: usa `--log Security` e filtra pelos Event IDs de auditoria do AD (ver [CLAUDE.md](CLAUDE.md)), rotulando cada evento com a ação correspondente | `--ad` |
| `--log` | Nome do log a consultar (padrão: `Application`, ou `Security` se `--ad`) | `--log System` |
| `--server` | Computador remoto a consultar (padrão: local) | `--server SRV01` |
| `--event-id` | IDs de evento, separados por vírgula | `--event-id 4624,4625` |
| `--level` | Níveis, separados por vírgula: `Error`, `Warning`, `Information`, `AuditSuccess`, `AuditFailure` | `--level Error,Warning` |
| `--source` | Filtra por origem do evento (substring, pode listar várias separadas por vírgula) | `--source MsiInstaller` |
| `--user` | Filtra por usuário (substring de `DOMINIO\usuario`) | `--user kever` |
| `--keyword` | Filtra por palavra-chave dentro da mensagem do evento | `--keyword "login"` |
| `--start` | Data/hora inicial (`AAAA-MM-DD` ou `AAAA-MM-DD HH:MM:SS`) | `--start 2026-08-01` |
| `--end` | Data/hora final | `--end 2026-08-30` |
| `--limit` | Número máximo de eventos retornados (padrão: 50) | `--limit 200` |
| `--output` | Formato de saída: `console` (padrão), `csv` ou `json` | `--output csv` |
| `--outfile` | Nome do arquivo de saída (obrigatório quando `--output` é `csv` ou `json`) — salvo automaticamente na pasta `csv/` ou `json/` do projeto, conforme `--output` | `--outfile eventos.csv` |
| `--watch` | Acompanha novos eventos em tempo real (ignora `--limit`/histórico) | `--watch` |
| `--interval` | Intervalo em segundos entre checagens no modo `--watch` (padrão: 2) | `--interval 5` |
| `--list-logs` | Lista os logs/canais disponíveis e encerra | `--list-logs` |
| `--list-ad-ids` | Lista os Event IDs de auditoria do AD conhecidos (ver [CLAUDE.md](CLAUDE.md)) e encerra | `--list-ad-ids` |

Os filtros podem ser combinados livremente.

## Exemplos

**Últimos 20 erros e avisos do log System:**

```powershell
python main.py --log System --level Error,Warning --limit 20
```

**Eventos de logon/logoff/AD em um período, exportados para CSV:**

```powershell
python main.py --ad --event-id 4624,4625,4634 --start "2026-08-01" --end "2026-08-30" --output csv --outfile logons.csv
```

**Buscar uma palavra-chave nas mensagens do Application, salvando em JSON:**

```powershell
python main.py --log Application --keyword "falha" --output json --outfile falhas.json
```

**Filtrar por origem e por usuário:**

```powershell
python main.py --log Application --source MsiInstaller --user kever
```

**Acompanhar novos eventos do log System em tempo real:**

```powershell
python main.py --log System --watch
```

Pressione `Ctrl+C` para interromper o modo `--watch`.

## Campos retornados

Cada evento contém:

- `record_number` – número do registro no log
- `time_generated` – data/hora de geração do evento
- `event_id` – ID do evento
- `action` – ação correspondente ao Event ID no modo `--ad` (vazio para eventos fora dessa lista)
- `level` – tipo (Error, Warning, Information, AuditSuccess, AuditFailure)
- `source` – origem (serviço/aplicativo que gerou o evento)
- `computer` – nome do computador
- `category` – categoria do evento
- `user` – usuário associado (quando disponível, resolvido a partir do SID)
- `message` – mensagem completa formatada do evento

## Observações

- A leitura é feita do evento mais recente para o mais antigo; ao usar `--start`, a busca para automaticamente assim que ultrapassa a data limite (mais eficiente para logs grandes).
- Se a mensagem completa do evento não puder ser resolvida (DLL de mensagens ausente), o texto retornado pode ficar vazio ou genérico — isso é uma limitação do próprio Windows, não do script.
- Consultar o log `Security`, ou logs de outro computador (`--server`), pode exigir privilégios de Administrador.
- Arquivos de `--output csv` são salvos em `csv/` e de `--output json` em `json/`, na raiz do projeto (as pastas são criadas automaticamente se não existirem); qualquer diretório informado junto ao nome em `--outfile` é ignorado, apenas o nome do arquivo é usado.
