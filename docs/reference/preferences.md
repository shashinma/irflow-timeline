---
description: Configure date/time display format, timezone, font size, and theme in IRFlow Timeline.
---

# Preferences

IRFlow Timeline preferences are accessible from the **Tools** menu in the macOS menu bar.

## Datetime Format

Control how timestamp columns are displayed in the grid. The underlying data is unchanged — formatting is applied at render time.

Access via **Tools > Datetime Format** and select a format:

| Format | Example |
|--------|---------|
| **Default (raw)** | Displays the original value as-is |
| `yyyy-MM-dd HH:mm:ss` | `2025-03-15 14:30:45` |
| `yyyy-MM-dd HH:mm:ss.fff` | `2025-03-15 14:30:45.123` |
| `yyyy-MM-dd HH:mm:ss.fffffff` | `2025-03-15 14:30:45.1234567` |
| `MM/dd/yyyy HH:mm:ss` | `03/15/2025 14:30:45` |
| `dd/MM/yyyy HH:mm:ss` | `15/03/2025 14:30:45` |
| `yyyy-MM-dd` | `2025-03-15` |

::: tip Sub-Second Precision
Use `yyyy-MM-dd HH:mm:ss.fffffff` for Sysmon and EVTX data where sub-second precision is forensically relevant — especially when correlating process creation with network connections.
:::

## Timezone

Convert timestamp display to a specific timezone. Access via **Tools > Timezone**.

| Timezone | IANA Identifier |
|----------|----------------|
| **UTC** | `UTC` |
| **US/Eastern** (EST/EDT) | `America/New_York` |
| **US/Central** (CST/CDT) | `America/Chicago` |
| **US/Mountain** (MST/MDT) | `America/Denver` |
| **US/Pacific** (PST/PDT) | `America/Los_Angeles` |
| **Europe/London** (GMT/BST) | `Europe/London` |
| **Europe/Berlin** (CET/CEST) | `Europe/Berlin` |
| **Asia/Tokyo** (JST) | `Asia/Tokyo` |
| **Asia/Shanghai** (CST) | `Asia/Shanghai` |
| **Australia/Sydney** (AEST/AEDT) | `Australia/Sydney` |
| **Local (system)** | Uses your macOS system timezone |

Timezone conversion is display-only. The raw timestamp values in the database remain unchanged, and exports use the original values.

::: tip DFIR Best Practice
Work in UTC during analysis to maintain consistency with log sources and other analysts. Switch to the local timezone of the compromised host only when correlating user activity or system events with physical-world timelines.
:::

## Font Size

Adjust the grid text size via **Tools > Font Size**. Available options:

- **Increase** — `Cmd+Plus`
- **Decrease** — `Cmd+-`
- Fixed sizes: 9px, 10px, 11px, 12px, 13px, 14px, 16px, 18px

Smaller sizes (9–10px) are useful for wide timelines with many columns. Larger sizes (14–18px) help when presenting findings or working on high-resolution displays.

## Theme

Toggle between **Dark** and **Light** mode via **View > Toggle Theme** or `Cmd+T`.

- **Dark** (default) — optimized for extended analysis sessions with a dark background and the Unit 42 orange accent color (`#E85D2A`)
- **Light** — white background with the same orange accent, designed for screen sharing and report preparation

Both themes apply consistently across the grid, modals, histogram, analytics panels, and all other UI elements.

## See Also

- [Keyboard Shortcuts](/reference/keyboard-shortcuts) — full list of keyboard shortcuts including preference toggles
- [Performance Tips](/reference/performance-tips) — smaller font sizes may improve rendering performance with wide datasets
- [Virtual Grid](/features/virtual-grid) — the main data interface where preferences take effect
