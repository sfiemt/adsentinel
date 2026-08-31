"""
main.py

Leitor/consulta de logs do Windows Event Viewer (Application, System, Security
ou qualquer outro log clássico) com filtros por ID de evento, nível/tipo,
origem, data, palavra-chave e usuário. Suporta saida em console, CSV ou JSON,
e um modo "watch" para acompanhar novos eventos em tempo real.

Requer Windows + pywin32 (pip install -r requirements.txt).
Para o log "Security" normalmente e necessario executar como Administrador.
"""

import argparse
import csv
import json
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

BASE_DIR = Path(__file__).resolve().parent

try:
    import win32evtlog
    import win32evtlogutil
    import win32security
    import win32con
except ImportError:
    print(
        "Este script requer o pacote 'pywin32'.\n"
        "Instale com: pip install -r requirements.txt",
        file=sys.stderr,
    )
    sys.exit(1)


EVENT_TYPE_NAMES = {
    win32con.EVENTLOG_ERROR_TYPE: "Error",
    win32con.EVENTLOG_WARNING_TYPE: "Warning",
    win32con.EVENTLOG_INFORMATION_TYPE: "Information",
    win32con.EVENTLOG_AUDIT_SUCCESS: "AuditSuccess",
    win32con.EVENTLOG_AUDIT_FAILURE: "AuditFailure",
}
EVENT_TYPE_BY_NAME = {v.lower(): k for k, v in EVENT_TYPE_NAMES.items()}

# Event IDs do log "Security" relevantes para monitoramento do Active
# Directory (ver CLAUDE.md). Usados pelo modo --ad para filtrar e para
# rotular cada evento com a acao correspondente.
AD_EVENT_ACTIONS = {
    4720: "Usuario criado",
    4722: "Usuario habilitado",
    4723: "Tentativa de alteracao de senha",
    4724: "Senha redefinida",
    4725: "Usuario desabilitado",
    4726: "Usuario excluido",
    4738: "Usuario alterado",
    4727: "Grupo global criado",
    4737: "Grupo global alterado",
    4728: "Usuario adicionado a grupo global",
    4729: "Usuario removido de grupo global",
    4732: "Usuario adicionado a grupo local",
    4733: "Usuario removido de grupo local",
    4740: "Conta bloqueada",
    4767: "Conta desbloqueada",
    4624: "Logon realizado",
    4625: "Falha de logon",
    4634: "Logoff",
    4648: "Logon usando credenciais explicitas",
    4662: "Operacao em objeto do AD",
    5136: "Objeto do AD modificado",
    5137: "Objeto do AD criado",
    5141: "Objeto do AD excluido",
    4739: "Politica de dominio alterada",
}
AD_EVENT_IDS = sorted(AD_EVENT_ACTIONS.keys())
AD_LOG_NAME = "Security"


@dataclass
class EventRecord:
    record_number: int
    time_generated: str
    event_id: int
    action: str
    level: str
    source: str
    computer: str
    category: int
    user: str
    message: str


def resolve_sid(sid) -> str:
    if sid is None:
        return ""
    try:
        name, domain, _ = win32security.LookupAccountSid(None, sid)
        return f"{domain}\\{name}"
    except Exception:
        return str(sid)


def to_event_record(raw, log_type: str) -> EventRecord:
    try:
        message = win32evtlogutil.SafeFormatMessage(raw, log_type)
    except Exception:
        message = ""
    event_id = raw.EventID & 0xFFFF
    return EventRecord(
        record_number=raw.RecordNumber,
        time_generated=raw.TimeGenerated.Format("%Y-%m-%d %H:%M:%S"),
        event_id=event_id,
        action=AD_EVENT_ACTIONS.get(event_id, ""),
        level=EVENT_TYPE_NAMES.get(raw.EventType, str(raw.EventType)),
        source=raw.SourceName,
        computer=raw.ComputerName,
        category=raw.EventCategory,
        user=resolve_sid(raw.Sid),
        message=(message or "").strip(),
    )


def matches_filters(rec: EventRecord, args) -> bool:
    if args.event_id and rec.event_id not in args.event_id:
        return False
    if args.level and rec.level.lower() not in args.level:
        return False
    if args.source and not any(s.lower() in rec.source.lower() for s in args.source):
        return False
    if args.user and args.user.lower() not in rec.user.lower():
        return False
    if args.keyword and args.keyword.lower() not in rec.message.lower():
        return False
    if args.start_date or args.end_date:
        ts = datetime.strptime(rec.time_generated, "%Y-%m-%d %H:%M:%S")
        if args.start_date and ts < args.start_date:
            return False
        if args.end_date and ts > args.end_date:
            return False
    return True


def read_events(log_type: str, server: Optional[str], args) -> Iterator[EventRecord]:
    handle = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    found = 0
    try:
        while found < args.limit:
            raw_events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not raw_events:
                break
            for raw in raw_events:
                rec = to_event_record(raw, log_type)
                # leitura e' do mais novo para o mais antigo; parar cedo
                # quando ja' passamos do inicio do intervalo de data pedido.
                if args.start_date:
                    ts = datetime.strptime(rec.time_generated, "%Y-%m-%d %H:%M:%S")
                    if ts < args.start_date:
                        return
                if matches_filters(rec, args):
                    yield rec
                    found += 1
                    if found >= args.limit:
                        return
    finally:
        win32evtlog.CloseEventLog(handle)


def watch_events(log_type: str, server: Optional[str], args) -> Iterator[EventRecord]:
    handle = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    try:
        last_record = win32evtlog.GetNumberOfEventLogRecords(handle)
        # posiciona no fim do log atual (ignora historico existente)
        try:
            while True:
                raw_events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not raw_events:
                    break
        except Exception:
            pass
        print(f"Aguardando novos eventos em '{log_type}' (Ctrl+C para sair)...")
        while True:
            time.sleep(args.interval)
            raw_events = win32evtlog.ReadEventLog(handle, flags, 0)
            for raw in raw_events or []:
                rec = to_event_record(raw, log_type)
                if matches_filters(rec, args):
                    yield rec
    finally:
        win32evtlog.CloseEventLog(handle)


def list_logs() -> None:
    try:
        handle = win32evtlog.EvtOpenChannelEnum()
        names = []
        while True:
            try:
                name = win32evtlog.EvtNextChannelPath(handle)
            except Exception:
                break
            if not name:
                break
            names.append(name)
        for name in sorted(names, key=str.lower):
            print(name)
    except Exception as exc:
        print(f"Nao foi possivel enumerar os logs via API moderna ({exc}).")
        print("Logs classicos comuns: Application, System, Security, Setup.")


def print_console(records) -> int:
    count = 0
    for rec in records:
        count += 1
        print("=" * 70)
        header = f"#{rec.record_number}\n{rec.time_generated}\n[{rec.level}]\nID Evento {rec.event_id}"
        if rec.action:
            header += f"  -  {rec.action}"
        print(header)
        print(f"Origem: {rec.source}\nComputador: {rec.computer}")
        if rec.user:
            print(f"Usuario: {rec.user}")
        if rec.message:
            print(f"Mensagem: {rec.message}")
    if count == 0:
        print("Nenhum evento encontrado com os filtros informados.")
    return count


def resolve_output_path(outfile: str, fmt: str) -> Path:
    """Salva sempre dentro do diretorio do proprio formato (./csv ou ./json),
    ignorando qualquer diretorio informado em --outfile."""
    subdir = BASE_DIR / fmt
    subdir.mkdir(parents=True, exist_ok=True)
    return subdir / Path(outfile).name


def write_csv(records, path: Path) -> int:
    count = 0
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(EventRecord.__dataclass_fields__.keys()))
        writer.writeheader()
        for rec in records:
            writer.writerow(asdict(rec))
            count += 1
    return count


def write_json(records, path: Path) -> int:
    data = [asdict(rec) for rec in records]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return len(data)


def parse_date(value: str) -> datetime:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(
        f"Data invalida: '{value}'. Use 'AAAA-MM-DD' ou 'AAAA-MM-DD HH:MM:SS'."
    )


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Consulta/monitora o Windows Event Viewer, com foco em auditoria do Active Directory."
    )
    parser.add_argument("--ad", action="store_true", help="Modo Active Directory: usa --log Security e os Event IDs de auditoria do AD (ver CLAUDE.md), a menos que --log/--event-id sejam informados explicitamente")
    parser.add_argument("--log", default=None, help="Nome do log (Application, System, Security, ...). Padrao: Application (Security se --ad)")
    parser.add_argument("--server", default=None, help="Computador remoto (padrao: local)")
    parser.add_argument("--event-id", default=None, help="IDs de evento, separados por virgula. Ex: 4624,4625")
    parser.add_argument("--level", default=None, help="Niveis, separados por virgula: Error,Warning,Information,AuditSuccess,AuditFailure")
    parser.add_argument("--source", default=None, help="Filtra por origem (substring, separadas por virgula)")
    parser.add_argument("--user", default=None, help="Filtra por usuario (substring do DOMINIO\\usuario)")
    parser.add_argument("--keyword", default=None, help="Filtra por palavra-chave na mensagem do evento")
    parser.add_argument("--start", dest="start_date", type=parse_date, default=None, help="Data/hora inicial (AAAA-MM-DD [HH:MM:SS])")
    parser.add_argument("--end", dest="end_date", type=parse_date, default=None, help="Data/hora final (AAAA-MM-DD [HH:MM:SS])")
    parser.add_argument("--limit", type=int, default=50, help="Numero maximo de eventos a retornar (padrao: 50)")
    parser.add_argument("--output", choices=["console", "csv", "json"], default="console", help="Formato de saida")
    parser.add_argument("--outfile", default=None, help="Nome do arquivo de saida (obrigatorio para csv/json). Sempre salvo em ./csv/ ou ./json/, conforme --output")
    parser.add_argument("--watch", action="store_true", help="Acompanha novos eventos em tempo real")
    parser.add_argument("--interval", type=float, default=2.0, help="Intervalo (s) de checagem no modo --watch")
    parser.add_argument("--list-logs", action="store_true", help="Lista os logs disponiveis e sai")
    parser.add_argument("--list-ad-ids", action="store_true", help="Lista os Event IDs de auditoria do AD conhecidos e sai")

    args = parser.parse_args(argv)

    explicit_event_id = args.event_id is not None
    args.event_id = [int(x) for x in args.event_id.split(",")] if args.event_id else None
    args.level = [x.strip().lower() for x in args.level.split(",")] if args.level else None
    args.source = [x.strip() for x in args.source.split(",")] if args.source else None

    if args.ad:
        if args.log is None:
            args.log = AD_LOG_NAME
        if not explicit_event_id:
            args.event_id = AD_EVENT_IDS
    elif args.log is None:
        args.log = "Application"

    return args


def main(argv=None) -> int:
    args = parse_args(argv)

    if args.list_logs:
        list_logs()
        return 0

    if args.list_ad_ids:
        for event_id, action in sorted(AD_EVENT_ACTIONS.items()):
            print(f"{event_id}\t{action}")
        return 0

    if args.output in ("csv", "json") and not args.outfile:
        print(f"--outfile e obrigatorio quando --output={args.output}", file=sys.stderr)
        return 2

    try:
        if args.watch:
            records = watch_events(args.log, args.server, args)
            for rec in records:
                print_console([rec])
            return 0

        records = list(read_events(args.log, args.server, args))

    except Exception as exc:
        print(f"Erro ao ler o log '{args.log}': {exc}", file=sys.stderr)
        print(
            "Dica: o log 'Security' geralmente exige executar este script como Administrador.",
            file=sys.stderr,
        )
        return 1

    if args.output == "console":
        n = print_console(records)
    elif args.output == "csv":
        out_path = resolve_output_path(args.outfile, "csv")
        n = write_csv(records, out_path)
        print(f"{n} evento(s) exportado(s) para {out_path}")
    else:
        out_path = resolve_output_path(args.outfile, "json")
        n = write_json(records, out_path)
        print(f"{n} evento(s) exportado(s) para {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
