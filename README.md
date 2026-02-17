# SnakeInMyBoot Repair Script

Hosted Windows recovery toolkit for WinRE USB recovery and safe in-Windows update prep.

## Files
- `fix.ps1`: Main repair script (`auto`, `kb`, `full`, `boot`, `repair`, `collect`, `undo`).
- `fix.ps1.sha256`: SHA-256 checksum for verified hosted update.
- `fixme.bat`: WinRE terminal menu (local-first, optional online update).
- `kb_targets.txt`: KB list checked for rollback.
- `telemetry.config.sample.ps1`: Optional Gmail/GitHub upload template.
- `windows_update_guard.ps1`: In-Windows restore-point + manual-update policy helper.
- `RUN-IN-WINDOWS.cmd`: Clickable launcher for `windows_update_guard.ps1`.
- `RUN-ROOTFIX.cmd`: Helper launcher that auto-finds USB letter.
- `CLIENT-INSTRUCTIONS.txt`: End-user walkthrough.

## WinRE recovery
Run `D:\RootFix\fixme.bat` from WinRE Command Prompt (use your USB letter).

## In-Windows safe update path
From File Explorer open USB, run `RootFix\RUN-IN-WINDOWS.cmd`, then choose option 1.
This sets manual update policy, creates a restore point, and opens Windows Update.

## Optional telemetry
Copy `telemetry.config.sample.ps1` to `telemetry.config.ps1`, fill credentials/tokens.
Logs upload only when explicitly configured.
