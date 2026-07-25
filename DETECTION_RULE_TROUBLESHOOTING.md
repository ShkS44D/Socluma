# Detection-rule troubleshooting

## Trace the pipeline

Use this order when a rule does not produce an alert:

1. Confirm the source event exists in Windows Event Viewer.
2. Confirm the collector subscribes to that event's channel.
3. Confirm the event appears in TriageOps Events.
4. Open the saved rule and use **Test Rule** with the event JSON.
5. Review the logsource, resolved fields, selections, and condition.
6. Check Alerts. A matching rule creates one alert for each event/rule pair.
7. Check correlation status. An isolated alert remains pending.

No service restart is required after a rule is created, edited, enabled, or
disabled. Enabled rules are loaded from the tenant-scoped database for every
event evaluation.

## Windows channels and audit policy

The Windows collector subscribes to `Security`, `System`, and `Application` by
default. Override the local list when required:

```text
WINDOWS_EVENT_CHANNELS=Security,System,Application
```

Run the collector with Event Log Reader privileges. Security events can also
require an audit policy. The collector reports a warning when it cannot verify
Plug and Play auditing; it never changes audit policy automatically.

For USB/Plug and Play Security Event 6416, an administrator must enable success
auditing:

```powershell
auditpol /set /subcategory:"Plug and Play Events" /success:enable
auditpol /get /subcategory:"Plug and Play Events"
```

Verify the source event independently:

```powershell
Get-WinEvent -FilterHashtable @{
  LogName = "Security"
  Id = 6416
  StartTime = (Get-Date).AddMinutes(-10)
} | Format-List TimeCreated, Id, RecordId, Message
```

If this returns nothing, Windows did not generate the event and no rule can
match it.

## USB storage rule

`DeviceId|contains: USBSTOR` is preferred because `ClassName: DiskDrive` can
also describe non-USB disks.

```yaml
title: USB Storage Device Connected
id: 5308ab7f-70c2-4a49-a7f8-753fd52c2188
status: test
description: Detects recognition of a USB storage device using Windows Security Event ID 6416.
author: Muhammad Saad Ahmed
logsource:
  product: windows
  service: security
  definition: Audit PNP Activity success auditing must be enabled.
detection:
  selection:
    EventID: 6416
    DeviceId|contains: USBSTOR
  condition: selection
falsepositives:
  - Approved removable storage devices
level: medium
```

For Process Creation Event 4688, first enable Process Creation success auditing
and verify the event in the Security channel. Rules can then match `EventID`,
`Image`/`NewProcessName`, and `CommandLine` where Windows records those fields.

## Supported Sigma subset

TriageOps supports:

- YAML or JSON rules with `title`, `logsource`, `detection`, and `condition`
- exact case-insensitive scalar equality and lists of accepted values
- `contains`, `startswith`, `endswith`, `all`, `re`, and `case_sensitive`
- `and`, `or`, `not`, and parentheses
- `1 of selection*`, `all of selection*`, `1 of them`, and `all of them`
- integer/string equivalence for fields such as `EventID`
- controlled Windows logsource aliases and nested EventData field resolution

Rules retain metadata such as `id`, `status`, `description`, `author`, dates,
references, tags, false positives, and level in parsed content. TriageOps
generates an ID when one is omitted.

Unsupported modifiers, unknown selections, invalid conditions, and unsupported
logsource keys are rejected when saved. TriageOps does not claim full Sigma
support. Aggregations, Sigma correlation rules, pipelines, and backend-specific
features outside the list above are unsupported.

## Events, alerts, and incidents

- A collected event is stored even when no rule matches.
- A matching enabled rule creates exactly one alert for that event/rule pair.
- A single alert remains **Pending correlation**.
- Incidents require multiple qualifying related alerts under the deterministic
  score, strong-identifier, time-window, and attack-stage policy.
- Repeating the same USB rule does not automatically constitute an attack chain.
