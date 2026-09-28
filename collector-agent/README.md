# VigilantAI Collector Agent

The VigilantAI collector agent sends host telemetry and heartbeat updates to the VigilantAI backend.

## Supported Platforms

- Windows: Windows Security Event Log collection when `pywin32` is available.
  Security events are forwarded with `EventID`, host metadata, record number,
  and the event's string inserts so tenant-authored detection rules can match
  fields exposed by Windows. Event 6416 is additionally normalized with Plug
  and Play device fields such as `DeviceId`, `DeviceDescription`, and
  `ClassName`.
- Linux: auth/syslog collection where readable.
- Other platforms: simulated development events.

## Install

```powershell
cd collector-agent
pip install -r requirements.txt
```

## Configure

Register a collector in VigilantAI first. The backend returns a collector ID and one-time token.

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
- Run the Windows collector with permission to read the Security event log.
  Windows must also have the relevant audit subcategory enabled. For USB/Plug
  and Play event 6416, enable successful Plug and Play auditing:

  ```powershell
  auditpol /set /subcategory:"Plug and Play Events" /success:enable
  ```

  A matching rule creates an alert. A single alert can remain pending because
  normal incidents require qualifying related alerts under the correlation
  policy.

## Rotate Collector Credentials

1. Sign in to VigilantAI as an authorized administrator or analyst for the intended organization.
2. Register a new collector and record the returned ID and one-time token in an approved secret store.
3. Stop the old collector process.
4. Update only the collector host's local configuration:

   ```text
   COLLECTOR_ID=<new-collector-id>
   COLLECTOR_TOKEN=<new-one-time-token>
   BACKEND_URL=https://<vigilantai-host>
   ```

5. Start the collector and verify a successful heartbeat and test event ingestion.
6. Confirm the resulting event, detection, alert, and incident belong to the expected organization.
7. Remove or disable the superseded collector registration after the replacement is stable.

Never place the returned token in source control, tickets, screenshots, shell history, or shared documentation.
