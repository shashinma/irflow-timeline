---
description: Analyst profiles for managing false positives — suppressions, baselines, and shareable profile files for the Process Inspector.
---

# Analyst Profiles

The Analyst Profile system lets you suppress known false positives and define environment baselines so the [Process Inspector](/features/process-tree) surfaces only actionable findings. Profiles are portable JSON files that can be shared across your team.

## Suppressions

Add suppression rules to hide known-good detections from Process Inspector results. Each suppression rule can match on one or more of the following fields:

| Field | Description |
|-------|-------------|
| **Process name** | The detected process (e.g., `svchost.exe`) |
| **Parent process name** | The parent in the chain |
| **Hostname** | Specific machine name |
| **User** | Account context |
| **Image path** | Full executable path |
| **Command line contains** | Substring match on command line arguments |
| **Reason** | Free-text justification for the suppression |

### Creating a Suppression

1. Open the **Process Inspector** panel
2. Find a detection you want to suppress
3. Click the suppression icon next to the detection
4. Fill in the matching fields — only fields you populate are used for matching
5. Add a reason describing why this is a known-good detection

Suppressed detections are hidden from Triage and Review modes but remain visible in Raw mode.

## Baselines

Define baseline behaviors that are normal for your environment. Baseline rules use the same matching fields as suppressions and serve as documentation of expected activity patterns.

Use baselines to record things like:
- Legitimate scheduled tasks that trigger persistence detections
- Expected parent-child process relationships in your environment
- Known-good services that match suspicious path patterns

## Saving and Loading Profiles

- **Save Profile** — exports your current suppressions and baselines to a JSON file
- **Load Profile** — imports a previously saved profile, merging with any existing rules

Profiles persist across sessions automatically. Use Save/Load to share profiles between analysts working the same engagement or to maintain per-client baseline configurations.

::: tip Team Workflow
Create a shared analyst profile per client or environment. When one analyst identifies a false positive, add it to the shared profile so the entire team benefits.
:::

## See Also

- [Process Inspector](/features/process-tree) — the primary consumer of analyst profiles
- [Persistence Analyzer](/features/persistence-analyzer) — custom rules complement analyst profiles for detection tuning
- [Sessions](/workflows/sessions) — analyst profiles persist independently of session save/restore
