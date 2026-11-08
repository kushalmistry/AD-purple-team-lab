# Lab Build

An isolated, host-only Active Directory lab. Nothing here touches a production network.

## Topology

| VM | OS | Role | RAM | IP (host-only) |
|---|---|---|---|---|
| DC01 | Windows Server 2022 (eval) | Domain controller, `lab.local` | 2-4 GB | 10.10.10.10 |
| WS01 | Windows 11 Enterprise (eval) | Domain workstation | 2-4 GB | 10.10.10.21 |
| WS02 | Windows 11 Enterprise (eval) | Domain workstation | 2-4 GB | 10.10.10.22 |
| KALI | Kali Linux | Attacker (follow TCM PEH AD sections) | 2 GB | 10.10.10.99 |

Hypervisor: VirtualBox or Hyper-V on an x86 host. Use a **host-only / internal network**
with no route to your home LAN. Snapshot every VM after setup so you can reset between runs.

Evaluation ISOs: Microsoft Evaluation Center (Windows Server 2022, Windows 11 Enterprise).

## Build steps

1. Install DC01, set a static IP, promote it to a DC for `lab.local`.
2. Create lab users and a service account with an SPN (the course walks through this).
3. Join WS01 and WS02 to the domain, pointing DNS at DC01.
4. Apply the logging configuration in [logging-setup.md](logging-setup.md) on **all** Windows VMs.
5. Snapshot everything as `baseline-logging`.

## Run loop (per technique)

1. Revert to `baseline-logging`.
2. Perform the technique from the matching PEH course section.
3. On the DC / target, run `scripts/Export-LabEvents.ps1` for the time window.
4. Copy the JSONL to your workstation and run `python tools/sigma_lite.py events.jsonl`.
5. Move the true-positive events into `tests/fixtures/<rule>/positive.jsonl`, add benign
   events from normal activity to `negative.jsonl`, and commit.
6. Write up the result in `docs/detections/<rule>.md` using the template.
