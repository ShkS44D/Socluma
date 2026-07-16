# TriageOps Collector Agent

The TriageOps collector agent sends host telemetry and heartbeat updates to the TriageOps backend.

## Supported Platforms

- Windows: Windows Security Event Log collection when `pywin32` is available.
- Linux: auth/syslog collection where readable.
- Other platforms: simulated development events.

## Install

```powershell
cd collector-agent
pip install -r requirements.txt
```

## Configure

Register a collector in TriageOps first. The backend returns a collector ID and one-time token.

Set:

```powershell
COLLECTOR_ID=<collector-id>
COLLECTOR_TOKEN=<collector-token>
BACKEND_URL=http://localhost:8001
```

For production, use an HTTPS backend URL.

## Run

```powershell
python main.py
```

The collector:

- Authenticates with `Authorization: Bearer <collector-token>`.
- Sends heartbeat requests to `/api/v1/collectors/{collector_id}/heartbeat`.
- Sends events to `/api/v1/events/ingest`.
- Adds an `X-Request-ID` header to outbound requests.
- Keeps file logging enabled with Windows-safe log rotation.

## Production Notes

- Run under a dedicated service account.
- Use HTTPS and normal certificate validation.
- Store the collector token in the host secret store or service manager, not in source control.
- Monitor collector logs for heartbeat or ingestion failures.
