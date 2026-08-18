# TriageOps Controlled Pilot Checklist

## Before A Pilot Session

- Confirm the selected organization is the intended test tenant.
- Confirm the backend, database, Redis, worker, frontend, and collector are healthy.
- Use synthetic or approved test telemetry only. Do not enter customer secrets, passwords, tokens, private keys, personal data, or confidential incident details.

## During Investigation

- Treat stored alerts, events, rules, timestamps, entities, and evidence references as confirmed only after opening the cited record.
- Treat Triage AI recommendations, hypotheses, containment guidance, and uncertainty statements as analyst assistance, not completed actions.
- Do not assume a Playbook, connector action, block, closure, or containment step occurred unless its execution record confirms completion.
- Record missing evidence and uncertain conclusions before changing incident status.

## Submit Feedback

- Use the Feedback page for general product feedback and include the affected page or workflow.
- For incorrect correlation, provide the incident ID, the alerts that should or should not be related, and the expected correlation reason. Do not paste secrets.
- For an incorrect AI claim, provide the incident ID, the question, the disputed claim, and the evidence record that supports or contradicts it.
- Mark whether the issue affects a confirmed fact, citation, timestamp, risk factor, MITRE mapping, recommendation, or missing-evidence statement.

## End Of Session

- Log out of the analyst account.
- Confirm no test credentials or tokens were copied into incident notes or feedback.
- Preserve request IDs and incident IDs needed for support while keeping authentication material private.
