import asyncio
import logging
import os
import sqlite3
import re
from datetime import date, datetime, timedelta, timezone
from urllib.parse import urlparse

import dns.resolver
import whois
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ChatAction
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_IDS = {
    int(value.strip())
    for value in os.getenv("ADMIN_IDS", "").split(",")
    if value.strip().isdigit()
}
DB_PATH = os.getenv("BOT_DB_PATH", "whoisdomain.sqlite3")
PRO_DAILY_LIMIT = 2
UTC = timezone.utc

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.INFO,
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("whoisdomain")

WELCOME = (
    "🌐 <b>WhoisDomain Bot</b>\n\n"
    "Look up domain registration details and DNS records.\n\n"
    "🔎 <code>/whois example.com</code>\n"
    "🧭 <code>/dns example.com</code>\n"
    "💳 <code>/credits</code> — view your balance\n"
    "⭐ <code>/pro</code> — view Pro status\n\n"
    "Pro users can make up to 2 searches per rolling 24 hours. "
    "Credits can be used for additional searches."
)

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\.?$"
)


def db_connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db_connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                credits INTEGER NOT NULL DEFAULT 0,
                pro_until TEXT DEFAULT NULL,
                joined_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS searches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                search_type TEXT NOT NULL,
                searched_at TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_searches_user_time ON searches(user_id, searched_at)")


def now_utc():
    return datetime.now(UTC)


def iso(dt):
    return dt.astimezone(UTC).isoformat(timespec="seconds")


def ensure_user(user_id: int):
    with db_connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO users(user_id, credits, pro_until, joined_at) VALUES (?, 0, NULL, ?)",
            (user_id, iso(now_utc())),
        )


def get_user(user_id: int):
    ensure_user(user_id)
    with db_connect() as conn:
        return conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()


def is_pro(user_id: int) -> bool:
    row = get_user(user_id)
    value = row["pro_until"]
    if not value:
        return False
    try:
        return datetime.fromisoformat(value) > now_utc()
    except ValueError:
        return False


def pro_expiry(user_id: int):
    row = get_user(user_id)
    value = row["pro_until"]
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        return dt if dt > now_utc() else None
    except ValueError:
        return None


def searches_last_24h(user_id: int) -> int:
    cutoff = iso(now_utc() - timedelta(hours=24))
    with db_connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM searches WHERE user_id = ? AND searched_at > ?",
            (user_id, cutoff),
        ).fetchone()
        return int(row["n"])


def get_credits(user_id: int) -> int:
    return int(get_user(user_id)["credits"])


def add_credits(user_id: int, amount: int) -> int:
    if amount <= 0:
        raise ValueError("Credit amount must be positive.")
    ensure_user(user_id)
    with db_connect() as conn:
        conn.execute("UPDATE users SET credits = credits + ? WHERE user_id = ?", (amount, user_id))
        row = conn.execute("SELECT credits FROM users WHERE user_id = ?", (user_id,)).fetchone()
        return int(row["credits"])


def set_pro_days(user_id: int, days: int) -> str:
    if days <= 0:
        raise ValueError("Days must be positive.")
    ensure_user(user_id)
    current = pro_expiry(user_id)
    start = current if current and current > now_utc() else now_utc()
    expiry = start + timedelta(days=days)
    with db_connect() as conn:
        conn.execute("UPDATE users SET pro_until = ? WHERE user_id = ?", (iso(expiry), user_id))
    return iso(expiry)


def remove_pro(user_id: int):
    ensure_user(user_id)
    with db_connect() as conn:
        conn.execute("UPDATE users SET pro_until = NULL WHERE user_id = ?", (user_id,))


def record_search(user_id: int, domain: str, search_type: str):
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO searches(user_id, domain, search_type, searched_at) VALUES (?, ?, ?, ?)",
            (user_id, domain, search_type, iso(now_utc())),
        )


def consume_search_access(user_id: int, domain: str, search_type: str):
    """
    Atomically decide access and record usage.
    Returns (allowed, reason, remaining_pro_searches, credits_left).
    A valid Pro subscription allows 2 searches per rolling 24h.
    When Pro's quota is used up, available credits can pay for extra searches.
    Non-Pro users need credits for searches.
    """
    ensure_user(user_id)
    now = now_utc()
    cutoff = iso(now - timedelta(hours=24))
    with db_connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        user = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
        pro_until = None
        if user["pro_until"]:
            try:
                candidate = datetime.fromisoformat(user["pro_until"])
                if candidate > now:
                    pro_until = candidate
            except ValueError:
                pass

        used = conn.execute(
            "SELECT COUNT(*) AS n FROM searches WHERE user_id = ? AND searched_at > ?",
            (user_id, cutoff),
        ).fetchone()["n"]

        credits = int(user["credits"])
        if pro_until and used < PRO_DAILY_LIMIT:
            conn.execute(
                "INSERT INTO searches(user_id, domain, search_type, searched_at) VALUES (?, ?, ?, ?)",
                (user_id, domain, search_type, iso(now)),
            )
            conn.commit()
            return True, "pro", PRO_DAILY_LIMIT - int(used) - 1, credits

        if credits > 0:
            conn.execute("UPDATE users SET credits = credits - 1 WHERE user_id = ?", (user_id,))
            conn.execute(
                "INSERT INTO searches(user_id, domain, search_type, searched_at) VALUES (?, ?, ?, ?)",
                (user_id, domain, search_type, iso(now)),
            )
            conn.commit()
            return True, "credit", max(0, PRO_DAILY_LIMIT - int(used)) if pro_until else 0, credits - 1

        conn.rollback()
        if pro_until:
            return False, "pro_limit", 0, credits
        return False, "no_access", 0, credits


def normalize_domain(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ValueError("Please provide a domain, for example: example.com")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        raise ValueError("I couldn't find a domain in that input.")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("That domain name isn't valid.")
    if not DOMAIN_RE.fullmatch(host):
        raise ValueError("Please enter a valid domain, such as <code>example.com</code>.")
    return host


def clean_value(value):
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        parts = [clean_value(v) for v in value]
        parts = [p for p in parts if p]
        return ", ".join(parts) if parts else None
    if isinstance(value, (datetime, date)):
        return value.strftime("%Y-%m-%d %H:%M UTC") if isinstance(value, datetime) else value.isoformat()
    text = str(value).strip()
    if not text or text.lower() in {"none", "null", "n/a", "not available"}:
        return None
    return text


def esc(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def get_whois(domain: str) -> str:
    result = whois.whois(domain)
    fields = [
        ("Registrar", "registrar"),
        ("Registrant / Organization", "org"),
        ("Created", "creation_date"),
        ("Expires", "expiration_date"),
        ("Updated", "updated_date"),
        ("Domain status", "status"),
        ("Name servers", "name_servers"),
        ("Country", "country"),
        ("Emails", "emails"),
    ]
    lines = [f"🔎 <b>WHOIS: {esc(domain)}</b>", ""]
    found = 0
    for label, key in fields:
        value = clean_value(getattr(result, key, None))
        if value:
            lines.append(f"<b>{label}:</b> {esc(value)}")
            found += 1
    if not found:
        lines.append("The registry returned no readable WHOIS fields. Some extensions require RDAP or limit public data.")
    lines.extend(["", "⚠️ <i>Data can be private, incomplete, or delayed.</i>"])
    return "\n".join(lines)


def get_dns(domain: str) -> str:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 5.0
    lines = [f"🧭 <b>DNS records: {esc(domain)}</b>", ""]
    for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            answers = resolver.resolve(domain, record_type, raise_on_no_answer=False)
            values = []
            if answers.rrset:
                for record in answers:
                    value = record.to_text()
                    if record_type == "TXT":
                        value = value.strip('"')
                    values.append(value)
            if values:
                lines.append(f"<b>{record_type}:</b>")
                for value in values[:8]:
                    lines.append(f"• <code>{esc(value[:300])}</code>")
        except Exception as exc:
            logger.debug("DNS %s lookup failed for %s: %s", record_type, domain, exc)
    if len(lines) == 2:
        lines.append("No public DNS records were found for these record types.")
    return "\n".join(lines)


def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("🔎 WHOIS help", callback_data="help_whois"),
         InlineKeyboardButton("🧭 DNS help", callback_data="help_dns")],
        [InlineKeyboardButton("💳 Credits", callback_data="credits"),
         InlineKeyboardButton("⭐ Pro", callback_data="pro")],
    ])
    await update.effective_message.reply_text(WELCOME, parse_mode="HTML", reply_markup=keyboard)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text(
        "📘 <b>Commands</b>\n\n"
        "/whois example.com — registration details\n"
        "/dns example.com — DNS records\n"
        "/credits — credit balance\n"
        "/pro — subscription and quota\n\n"
        "Admin commands:\n"
        "/addcredits USER_ID AMOUNT\n"
        "/setcredits USER_ID AMOUNT\n"
        "/addpro USER_ID DAYS\n"
        "/removepro USER_ID\n"
        "/userinfo USER_ID\n",
        parse_mode="HTML",
    )


async def credits_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    await update.effective_message.reply_text(
        f"💳 <b>Your credits:</b> {get_credits(uid)}\n\n"
        "Each credit pays for one additional successful lookup.",
        parse_mode="HTML",
    )


async def pro_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    expiry = pro_expiry(uid)
    used = searches_last_24h(uid)
    if expiry:
        remaining = max(0, PRO_DAILY_LIMIT - used)
        text = (
            "⭐ <b>Pro subscription: ACTIVE</b>\n"
            f"📅 Expires: <code>{esc(expiry.strftime('%Y-%m-%d %H:%M UTC'))}</code>\n"
            f"🔎 Pro searches used: <b>{min(used, PRO_DAILY_LIMIT)}/{PRO_DAILY_LIMIT}</b> in the last 24 hours\n"
            f"✅ Pro searches remaining: <b>{remaining}</b>\n"
            f"💳 Extra credits: <b>{get_credits(uid)}</b>"
        )
    else:
        text = (
            "⭐ <b>Pro subscription: INACTIVE</b>\n"
            f"💳 Credits available: <b>{get_credits(uid)}</b>\n\n"
            "A Pro subscription is assigned by the bot admin. "
            "Without Pro, each lookup requires one credit."
        )
    await update.effective_message.reply_text(text, parse_mode="HTML")


async def admin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_admin(uid):
        await update.effective_message.reply_text("⛔ Admin only.")
        return
    await update.effective_message.reply_text(
        "🛠️ <b>Admin commands</b>\n\n"
        "/addcredits USER_ID AMOUNT — add credits\n"
        "/setcredits USER_ID AMOUNT — set exact balance\n"
        "/addpro USER_ID DAYS — grant/extend Pro\n"
        "/removepro USER_ID — revoke Pro\n"
        "/userinfo USER_ID — inspect user account\n\n"
        "Example: <code>/addcredits 123456789 10</code>",
        parse_mode="HTML",
    )


def parse_positive_int(value, label):
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} must be a whole number.")
    if number <= 0:
        raise ValueError(f"{label} must be greater than zero.")
    return number


async def addcredits_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.effective_message.reply_text("⛔ Admin only.")
        return
    try:
        if len(context.args) != 2:
            raise ValueError("Usage: /addcredits USER_ID AMOUNT")
        target = parse_positive_int(context.args[0], "USER_ID")
        amount = parse_positive_int(context.args[1], "AMOUNT")
        balance = add_credits(target, amount)
        await update.effective_message.reply_text(
            f"✅ Added {amount} credits to <code>{target}</code>.\nNew balance: <b>{balance}</b>",
            parse_mode="HTML",
        )
    except ValueError as exc:
        await update.effective_message.reply_text(esc(str(exc)), parse_mode="HTML")


async def setcredits_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.effective_message.reply_text("⛔ Admin only.")
        return
    try:
        if len(context.args) != 2:
            raise ValueError("Usage: /setcredits USER_ID AMOUNT")
        target = parse_positive_int(context.args[0], "USER_ID")
        amount = int(context.args[1])
        if amount < 0:
            raise ValueError("AMOUNT cannot be negative.")
        ensure_user(target)
        with db_connect() as conn:
            conn.execute("UPDATE users SET credits = ? WHERE user_id = ?", (amount, target))
        await update.effective_message.reply_text(
            f"✅ Credits for <code>{target}</code> set to <b>{amount}</b>.", parse_mode="HTML"
        )
    except ValueError as exc:
        await update.effective_message.reply_text(esc(str(exc)), parse_mode="HTML")


async def addpro_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.effective_message.reply_text("⛔ Admin only.")
        return
    try:
        if len(context.args) != 2:
            raise ValueError("Usage: /addpro USER_ID DAYS")
        target = parse_positive_int(context.args[0], "USER_ID")
        days = parse_positive_int(context.args[1], "DAYS")
        expiry = set_pro_days(target, days)
        await update.effective_message.reply_text(
            f"⭐ Pro granted/extended for <code>{target}</code>.\nExpires: <code>{esc(expiry)}</code>",
            parse_mode="HTML",
        )
    except ValueError as exc:
        await update.effective_message.reply_text(esc(str(exc)), parse_mode="HTML")


async def removepro_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.effective_message.reply_text("⛔ Admin only.")
        return
    try:
        if len(context.args) != 1:
            raise ValueError("Usage: /removepro USER_ID")
        target = parse_positive_int(context.args[0], "USER_ID")
        remove_pro(target)
        await update.effective_message.reply_text(f"✅ Pro removed from <code>{target}</code>.", parse_mode="HTML")
    except ValueError as exc:
        await update.effective_message.reply_text(esc(str(exc)), parse_mode="HTML")


async def userinfo_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.effective_message.reply_text("⛔ Admin only.")
        return
    try:
        if len(context.args) != 1:
            raise ValueError("Usage: /userinfo USER_ID")
        target = parse_positive_int(context.args[0], "USER_ID")
        row = get_user(target)
        expiry = pro_expiry(target)
        await update.effective_message.reply_text(
            f"👤 <b>User:</b> <code>{target}</code>\n"
            f"💳 <b>Credits:</b> {row['credits']}\n"
            f"⭐ <b>Pro active:</b> {'Yes' if expiry else 'No'}\n"
            f"📅 <b>Pro expiry:</b> {esc(expiry.isoformat() if expiry else '—')}\n"
            f"🔎 <b>Searches last 24h:</b> {searches_last_24h(target)}",
            parse_mode="HTML",
        )
    except ValueError as exc:
        await update.effective_message.reply_text(esc(str(exc)), parse_mode="HTML")


async def do_lookup(update: Update, context: ContextTypes.DEFAULT_TYPE, mode: str, raw: str):
    message = update.effective_message
    uid = update.effective_user.id
    try:
        domain = normalize_domain(raw)
    except ValueError as exc:
        await message.reply_text(str(exc), parse_mode="HTML")
        return

    allowed, reason, remaining, credits_left = consume_search_access(uid, domain, mode)
    if not allowed:
        if reason == "pro_limit":
            text = (
                "⏳ <b>Pro daily limit reached</b>\n\n"
                "Your Pro plan includes 2 searches per rolling 24 hours. "
                "You can wait until a previous search is older than 24 hours, "
                "or use credits for extra lookups.\n\n"
                f"💳 Credits available: <b>{credits_left}</b>\nUse /credits to check your balance."
            )
        else:
            text = (
                "🔒 <b>Search access required</b>\n\n"
                "You need an active Pro subscription or at least 1 credit to search.\n"
                "Contact the bot administrator to request access.\n\n"
                "Use /credits and /pro to check your account."
            )
        await message.reply_text(text, parse_mode="HTML")
        return

    await message.chat.send_action(ChatAction.TYPING)
    status = await message.reply_text(
        f"⏳ Checking <code>{esc(domain)}</code>…", parse_mode="HTML"
    )
    try:
        if mode == "whois":
            output = await asyncio.wait_for(asyncio.to_thread(get_whois, domain), timeout=20)
        else:
            output = await asyncio.wait_for(asyncio.to_thread(get_dns, domain), timeout=20)

        if reason == "pro":
            footer = f"\n\n⭐ Pro searches remaining in last-24h quota: <b>{remaining}</b>"
        else:
            footer = f"\n\n💳 Credit used. Remaining credits: <b>{credits_left}</b>"
        await status.edit_text(output + footer, parse_mode="HTML", disable_web_page_preview=True)
    except asyncio.TimeoutError:
        await status.edit_text(
            "⌛ Lookup timed out. Your search access was used for this attempt; contact the admin if the service keeps failing."
        )
    except Exception as exc:
        logger.info("%s lookup failed for %s: %s", mode, domain, exc)
        await status.edit_text(
            "❌ Lookup failed or the registry didn't respond. Your search access was used for this attempt. Try again later.",
            parse_mode="HTML",
        )


async def whois_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    raw = " ".join(context.args)
    if not raw:
        await update.effective_message.reply_text("Usage: <code>/whois example.com</code>", parse_mode="HTML")
        return
    await do_lookup(update, context, "whois", raw)


async def dns_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    raw = " ".join(context.args)
    if not raw:
        await update.effective_message.reply_text("Usage: <code>/dns example.com</code>", parse_mode="HTML")
        return
    await do_lookup(update, context, "dns", raw)


async def text_domain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await do_lookup(update, context, "whois", update.effective_message.text or "")


async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.data == "help_whois":
        await query.message.reply_text("Use <code>/whois example.com</code>", parse_mode="HTML")
    elif query.data == "help_dns":
        await query.message.reply_text("Use <code>/dns example.com</code>", parse_mode="HTML")
    elif query.data == "credits":
        await query.message.reply_text(f"💳 Your balance: <b>{get_credits(query.from_user.id)}</b>", parse_mode="HTML")
    elif query.data == "pro":
        await query.message.reply_text("Use /pro to see subscription expiry and your 24-hour search quota.")
    else:
        await query.message.reply_text("Use /whois example.com or /dns example.com.")


def main():
    if not BOT_TOKEN:
        raise SystemExit("Missing BOT_TOKEN environment variable.")
    init_db()
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("credits", credits_command))
    app.add_handler(CommandHandler("pro", pro_command))
    app.add_handler(CommandHandler("admin", admin_command))
    app.add_handler(CommandHandler("addcredits", addcredits_command))
    app.add_handler(CommandHandler("setcredits", setcredits_command))
    app.add_handler(CommandHandler("addpro", addpro_command))
    app.add_handler(CommandHandler("removepro", removepro_command))
    app.add_handler(CommandHandler("userinfo", userinfo_command))
    app.add_handler(CommandHandler("whois", whois_command))
    app.add_handler(CommandHandler("dns", dns_command))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_domain))
    logger.info("WhoisDomain bot starting…")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
