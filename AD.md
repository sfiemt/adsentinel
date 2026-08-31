# Event Viewer AD Monitor

## Finalidade

Monitorar eventos do **Active Directory** (via log **Security** dos Domain
Controllers/Windows) para acompanhar ações administrativas e de segurança:
criação/exclusão/alteração de usuários e grupos, logons/logoffs, bloqueios de
conta e mudanças em objetos do AD e na política de domínio.

O programa principal é [main.py](main.py), que lê o Event
Viewer do Windows via `pywin32`, filtra por Event ID/nível/origem/data/usuário
e exporta os resultados (console, CSV ou JSON), incluindo um modo `--watch`
para acompanhamento em tempo real — usado aqui para vigiar os Event IDs do AD
listados abaixo.

## Event IDs de interesse (Active Directory)

| Event ID | Ação |
|---|---|
| [4720](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720) | Usuário criado |
| [4722](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4722) | Usuário habilitado |
| [4723](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4723) | Tentativa de alteração de senha |
| [4724](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4724) | Senha redefinida |
| [4725](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4725) | Usuário desabilitado |
| [4726](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4726) | Usuário excluído |
| [4738](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4738) | Usuário alterado |
| [4727](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4731) | Grupo global criado |
| [4737](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4735) | Grupo global alterado |
| [4728](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732) | Usuário adicionado a grupo global |
| [4729](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4733) | Usuário removido de grupo global |
| [4732](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732) | Usuário adicionado a grupo local |
| [4733](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4733) | Usuário removido de grupo local |
| [4740](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740) | Conta bloqueada |
| [4767](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4767) | Conta desbloqueada |
| [4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) | Logon realizado |
| [4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625) | Falha de logon |
| [4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634) | Logoff |
| [4648](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648) | Logon usando credenciais explícitas |
| [4662](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662) | Operação em objeto do AD |
| [5136](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136) | Objeto do AD modificado |
| [5137](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5137) | Objeto do AD criado |
| [5141](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5141) | Objeto do AD excluído |
| [4739](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4739) | Política de domínio alterada |

Esses IDs vivem no log `Security`. Ler esse log normalmente exige executar
como Administrador (e, no caso de um Domain Controller, a Auditoria de
Diretório precisa estar habilitada via GPO para os eventos 4662/5136/5137/5141
serem gerados).

> A Microsoft não documenta 4727/4728/4729/4737 em páginas próprias — ela
> reaproveita a página do evento equivalente para **grupo local**, já que os
> campos, o XML e as recomendações são idênticos (só muda o tipo de grupo,
> global em vez de local): 4727→4731, 4728→4732, 4729→4733, 4737→4735.

## Uso típico para monitoramento do AD

O programa tem um modo dedicado `--ad`: ele já aplica `--log Security` e filtra
automaticamente pelos 24 Event IDs da tabela acima, além de rotular cada
evento retornado com a coluna/campo `action` (a "Ação" correspondente).

Consultar o histórico recente:

```powershell
python main.py --ad --limit 200 --output csv --outfile ad_events.csv
```

Acompanhar esses eventos em tempo real:

```powershell
python main.py --ad --watch
```

Combinar com outros filtros (ex: apenas um usuário, ou um subconjunto de IDs):

```powershell
python main.py --ad --user "joao.silva"
python main.py --ad --event-id 4625,4740,4767   # so falhas de logon e bloqueios/desbloqueios
```

Ver a tabela de IDs suportados a qualquer momento:

```powershell
python main.py --list-ad-ids
```

Veja [README.md](README.md) para a lista completa de opções e exemplos de uso
do programa.
