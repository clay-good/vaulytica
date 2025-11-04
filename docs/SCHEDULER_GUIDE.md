# Scheduler Guide

**Vaulytica Scheduled Scan Automation**

---

## Overview

Vaulytica includes a built-in scheduler for automated recurring scans. The scheduler uses APScheduler to provide cron-like scheduling with support for:

- **Cron expressions** (e.g., "0 2 * * *" for daily at 2 AM)
- **Interval expressions** (e.g., "6h" for every 6 hours)
- **Multiple scan types** (files, users, Gmail, shared drives, OAuth)
- **Persistent schedules** (saved to disk, survive restarts)
- **Daemon mode** (run in background)

---

## Quick Start

### 1. Add a Schedule

```bash
# Daily file scan at 2 AM
vaulytica schedule add \
  --name "Daily File Scan" \
  --scan-type files \
  --schedule "0 2 * * *"

# User scan every 6 hours
vaulytica schedule add \
  --name "Periodic User Scan" \
  --scan-type users \
  --schedule-type interval \
  --schedule "6h"

# Gmail scan every 30 minutes
vaulytica schedule add \
  --name "Gmail Monitor" \
  --scan-type gmail \
  --schedule-type interval \
  --schedule "30m"
```

### 2. List Schedules

```bash
# List all schedules
vaulytica schedule list

# List only enabled schedules
vaulytica schedule list --enabled-only
```

### 3. Run the Scheduler

```bash
# Run in foreground (blocking, press Ctrl+C to stop)
vaulytica schedule run

# Run as daemon (background)
vaulytica schedule run --daemon
```

---

## CLI Commands

### `schedule add`

Add a new scheduled scan.

**Options:**
- `--name, -n` (required): Schedule name
- `--scan-type, -t` (required): Type of scan (files, users, gmail, shared_drives, oauth)
- `--schedule-type` (default: cron): Schedule type (cron, interval)
- `--schedule, -s` (required): Schedule expression
- `--config, -c`: Scan configuration (JSON string)
- `--enabled/--disabled` (default: enabled): Enable immediately

**Examples:**

```bash
# Daily file scan at 2 AM
vaulytica schedule add -n "Daily File Scan" -t files -s "0 2 * * *"

# User scan every 6 hours
vaulytica schedule add -n "Periodic User Scan" -t users --schedule-type interval -s "6h"

# Gmail scan with custom config
vaulytica schedule add \
  -n "Gmail External Monitor" \
  -t gmail \
  --schedule-type interval \
  -s "30m" \
  --config '{"max_results": 500}'

# Disabled schedule (add but don't enable)
vaulytica schedule add -n "Weekend Scan" -t files -s "0 2 * * 6" --disabled
```

---

### `schedule list`

List all scheduled scans.

**Options:**
- `--enabled-only`: Only show enabled schedules

**Example:**

```bash
vaulytica schedule list
```

**Output:**

```
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┓
┃ ID                 ┃ Name               ┃ Type  ┃ Schedule   ┃ Enabled ┃ Runs ┃ Failures ┃ Last Run            ┃ Next Run            ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━┩
│ files_1730217600   │ Daily File Scan    │ files │ 0 2 * * *  │ ✓       │ 5    │ 0        │ 2025-10-29T02:00:00 │ 2025-10-30T02:00:00 │
│ users_1730217650   │ Periodic User Scan │ users │ 6h         │ ✓       │ 12   │ 0        │ 2025-10-29T08:00:00 │ 2025-10-29T14:00:00 │
│ gmail_1730217700   │ Gmail Monitor      │ gmail │ 30m        │ ✓       │ 48   │ 1        │ 2025-10-29T12:30:00 │ 2025-10-29T13:00:00 │
└────────────────────┴────────────────────┴───────┴────────────┴─────────┴──────┴──────────┴─────────────────────┴─────────────────────┘
```

---

### `schedule show`

Show details of a scheduled scan.

**Usage:**

```bash
vaulytica schedule show <scan_id>
```

**Example:**

```bash
vaulytica schedule show files_1730217600
```

**Output:**

```
╭─────────────────────── Schedule Details ───────────────────────╮
│                                                                 │
│ Name: Daily File Scan                                           │
│ ID: files_1730217600                                            │
│ Type: files                                                     │
│ Schedule Type: cron                                             │
│ Schedule: 0 2 * * *                                             │
│ Enabled: Yes                                                    │
│                                                                 │
│ Statistics:                                                     │
│   Run Count: 5                                                  │
│   Failure Count: 0                                              │
│   Last Run: 2025-10-29T02:00:00                                 │
│   Next Run: 2025-10-30T02:00:00                                 │
│                                                                 │
│ Timestamps:                                                     │
│   Created: 2025-10-28T10:00:00                                  │
│   Updated: 2025-10-29T02:00:00                                  │
│                                                                 │
│ Configuration:                                                  │
│   (none)                                                        │
╰─────────────────────────────────────────────────────────────────╯
```

---

### `schedule remove`

Remove a scheduled scan.

**Options:**
- `--yes, -y`: Skip confirmation

**Usage:**

```bash
vaulytica schedule remove <scan_id>
```

**Example:**

```bash
# With confirmation
vaulytica schedule remove files_1730217600

# Skip confirmation
vaulytica schedule remove files_1730217600 --yes
```

---

### `schedule enable`

Enable a disabled schedule.

**Usage:**

```bash
vaulytica schedule enable <scan_id>
```

**Example:**

```bash
vaulytica schedule enable files_1730217600
```

---

### `schedule disable`

Disable an enabled schedule.

**Usage:**

```bash
vaulytica schedule disable <scan_id>
```

**Example:**

```bash
vaulytica schedule disable files_1730217600
```

---

### `schedule run`

Start the scheduler to run scheduled scans.

**Options:**
- `--daemon, -d`: Run as daemon (background process)

**Usage:**

```bash
# Run in foreground (blocking)
vaulytica schedule run

# Run as daemon (background)
vaulytica schedule run --daemon
```

**Example:**

```bash
# Foreground mode (press Ctrl+C to stop)
vaulytica schedule run
```

**Output:**

```
Starting scheduler (press Ctrl+C to stop)...
  Active jobs: 3

[2025-10-29 14:00:00] scan_started: Daily File Scan
[2025-10-29 14:05:23] scan_completed: Daily File Scan (duration: 5.23s)
```

---

### `schedule stop`

Stop the scheduler (if running as daemon).

**Usage:**

```bash
vaulytica schedule stop
```

---

## Schedule Expressions

### Cron Expressions

Cron expressions use 5 fields: `minute hour day month day_of_week`

**Examples:**

```bash
# Every day at 2 AM
"0 2 * * *"

# Every Monday at 9 AM
"0 9 * * 1"

# Every 15 minutes
"*/15 * * * *"

# First day of every month at midnight
"0 0 1 * *"

# Weekdays at 6 PM
"0 18 * * 1-5"

# Every 6 hours
"0 */6 * * *"
```

**Cron Field Values:**

| Field        | Values          | Special Characters |
| ------------ | --------------- | ------------------ |
| Minute       | 0-59            | `*` `,` `-` `/`    |
| Hour         | 0-23            | `*` `,` `-` `/`    |
| Day          | 1-31            | `*` `,` `-` `/`    |
| Month        | 1-12            | `*` `,` `-` `/`    |
| Day of Week  | 0-6 (0=Sunday)  | `*` `,` `-` `/`    |

---

### Interval Expressions

Interval expressions use a number followed by a unit: `<number><unit>`

**Units:**
- `s` - seconds
- `m` - minutes
- `h` - hours
- `d` - days

**Examples:**

```bash
# Every 30 seconds
"30s"

# Every 5 minutes
"5m"

# Every 6 hours
"6h"

# Every 2 days
"2d"
```

---

## Configuration File

Schedules are stored in `~/.vaulytica/schedules.json`:

```json
{
  "schedules": [
    {
      "id": "files_1730217600",
      "name": "Daily File Scan",
      "scan_type": "files",
      "schedule_type": "cron",
      "schedule": "0 2 * * *",
      "enabled": true,
      "config": {},
      "last_run": "2025-10-29T02:00:00",
      "next_run": "2025-10-30T02:00:00",
      "run_count": 5,
      "failure_count": 0,
      "created_at": "2025-10-28T10:00:00",
      "updated_at": "2025-10-29T02:00:00"
    }
  ],
  "updated_at": "2025-10-29T12:00:00"
}
```

---

## Best Practices

### 1. Start with Conservative Schedules

```bash
# Start with daily scans
vaulytica schedule add -n "Daily Scan" -t files -s "0 2 * * *"

# Gradually increase frequency if needed
vaulytica schedule add -n "Frequent Scan" -t files --schedule-type interval -s "6h"
```

### 2. Monitor Performance

```bash
# Check run statistics
vaulytica schedule list

# View detailed stats
vaulytica schedule show <scan_id>
```

### 3. Use Off-Peak Hours

```bash
# Schedule during off-peak hours (2-4 AM)
vaulytica schedule add -n "Nightly Scan" -t files -s "0 2 * * *"
```

### 4. Separate Scan Types

```bash
# Different schedules for different scan types
vaulytica schedule add -n "File Scan" -t files -s "0 2 * * *"
vaulytica schedule add -n "User Scan" -t users -s "0 3 * * *"
vaulytica schedule add -n "Gmail Scan" -t gmail -s "0 4 * * *"
```

### 5. Use Daemon Mode for Production

```bash
# Run as daemon
vaulytica schedule run --daemon

# Or use systemd (see DEPLOYMENT.md)
```

---

## Troubleshooting

### Issue: Schedule Not Running

**Check if scheduler is running:**

```bash
vaulytica schedule list
```

**Start the scheduler:**

```bash
vaulytica schedule run
```

---

### Issue: Schedule Failing

**Check failure count:**

```bash
vaulytica schedule show <scan_id>
```

**Check logs:**

```bash
tail -f ~/.vaulytica/logs/scheduler.log
```

---

### Issue: Wrong Schedule Time

**Verify schedule expression:**

```bash
vaulytica schedule show <scan_id>
```

**Update schedule (remove and re-add):**

```bash
vaulytica schedule remove <scan_id> --yes
vaulytica schedule add -n "New Schedule" -t files -s "0 3 * * *"
```

---

## Integration with Systemd

Create a systemd service for the scheduler:

```ini
[Unit]
Description=Vaulytica Scheduler
After=network.target

[Service]
Type=simple
User=vaulytica
WorkingDirectory=/opt/vaulytica
ExecStart=/usr/local/bin/vaulytica schedule run
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable and start:**

```bash
sudo systemctl enable vaulytica-scheduler
sudo systemctl start vaulytica-scheduler
sudo systemctl status vaulytica-scheduler
```

---

## Next Steps

- [Deployment Guide](DEPLOYMENT.md)
- [Webhook Integration Guide](WEBHOOK_GUIDE.md)
- [Getting Started Guide](GETTING_STARTED.md)

