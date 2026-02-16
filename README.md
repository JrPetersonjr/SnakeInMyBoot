# SnakeInMyBoot Repair Script

Hosted Windows recovery script used by `RootFix\\fixme.bat`.

## Files
- `fix.ps1`: Main repair script executed in WinRE.
- `fix.ps1.sha256`: SHA-256 checksum used to verify downloaded `fix.ps1`.
- `fixme.bat`: USB bootstrap + terminal menu (local-first, optional verified update).
- `CLIENT-INSTRUCTIONS.txt`: End-user walkthrough.

## Run Modes
- Default: `X:\RootFix\fixme.bat` then choose from menu.
- Quick auto: `X:\RootFix\fixme.bat auto`
- Auto + online verified update: `X:\RootFix\fixme.bat update`

## Hosted URLs
- Script: `https://raw.githubusercontent.com/JrPetersonjr/SnakeInMyBoot/master/fix.ps1`
- Hash: `https://raw.githubusercontent.com/JrPetersonjr/SnakeInMyBoot/master/fix.ps1.sha256`
