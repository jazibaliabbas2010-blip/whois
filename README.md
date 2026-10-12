# WhoisDomain Bot — Python + Credits + Pro

## Included
- WHOIS and DNS lookup commands
- SQLite database created automatically
- Admin credit management
- Admin Pro subscription management
- Pro quota: 2 searches in a rolling 24-hour window
- Additional searches consume credits
- No payment integration; admin assigns credits and Pro manually

## Requirements
Python 3.10+ recommended.

Install:
```bash
pip install -r requirements.txt
```

## Configure admin and token

Linux/macOS:
```bash
export BOT_TOKEN="YOUR_TELEGRAM_BOT_TOKEN"
export ADMIN_IDS="YOUR_TELEGRAM_NUMERIC_USER_ID"
python main.py
```

Multiple admins:
```bash
export ADMIN_IDS="123456789,987654321"
```

Windows PowerShell:
```powershell
$env:BOT_TOKEN="YOUR_TELEGRAM_BOT_TOKEN"
$env:ADMIN_IDS="123456789"
python main.py
```

Keep the token private. Only IDs listed in `ADMIN_IDS` can run admin commands.

## User commands
- `/start`
- `/help`
- `/whois example.com`
- `/dns example.com`
- `/credits`
- `/pro`

Users without Pro need credits. Each lookup uses one credit. Active Pro users get two lookups per rolling 24 hours; once the quota is reached, they can use credits for extra searches.

## Admin commands
- `/admin`
- `/addcredits USER_ID AMOUNT`
- `/setcredits USER_ID AMOUNT`
- `/addpro USER_ID DAYS`
- `/removepro USER_ID`
- `/userinfo USER_ID`

Example:
```text
/addcredits 123456789 20
/addpro 123456789 30
/setcredits 123456789 5
/removepro 123456789
/userinfo 123456789
```

To get a user's numeric Telegram ID, ask them to message the bot first, then use the ID they share with you or use a trusted Telegram ID bot.

## Notes
- This script uses long polling; keep the process running.
- WHOIS coverage differs by TLD. Some registries limit queries or conceal personal registration data.
- Credits and subscriptions are manually assigned by admins; this script does not process payments.
- Search attempts are counted when access is granted, even if the upstream WHOIS service fails or times out.
