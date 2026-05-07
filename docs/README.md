# Docs

> **Network architecture and incident reports from real detections inside the lab**

---

A SOC environment is only as credible as the work it produces. This folder is the paper trail — the network diagram that shows how every component fits together, and the incident reports that document detections fired by the live pipeline. Each report walks through what was observed, how Splunk and Suricata surfaced it, what the investigation found, and how it was remediated. The format mirrors what gets written up after a real shift on a SOC desk.

---

## Contents

| Document | Purpose |
|---|---|
| [architecture.md](./architecture.md) | Network topology, log flow, and port registry for the lab |
| [incident-reports/](./incident-reports/) | Investigation write-ups for detections triggered in the lab |

---

## Incident Reports

| Report | Date | Technique | Severity |
|---|---|---|---|
| [SSH Brute Force](./incident-reports/SSH-Brute-Force-2026-04.md) | 2026-04-15 | T1110 — Brute Force | Medium |

Each report follows the same structure: summary, timeline, detection logic, investigation steps, response actions, lessons learned, and artifacts. The intent is that anyone reading them can reconstruct exactly what happened and what the SPL queries surfaced at each step.
