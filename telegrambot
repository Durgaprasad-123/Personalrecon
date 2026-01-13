#!/usr/bin/env python3
import asyncio
import os
import time
import uuid
import shutil
import logging
from pathlib import Path

from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
)

from telethon import TelegramClient

# =====================================================
# CONFIG
# =====================================================

BOT_TOKEN = "BOT-TOKEN"
ALLOWED_USER_ID = USER---ID  # your Telegram numeric ID

# Telethon (for large uploads)
API_ID = xxxxxxxxx
API_HASH = "API_HASH_ID"
SESSION_NAME = "recon_user"
CHANNEL_ID = -100123456789 

# Paths
BASE_DIR = Path("/home/ubuntu/ai-recon-bot")
RECON_SCRIPT = BASE_DIR / "recon/recon.sh"
FFUF_SCRIPT = BASE_DIR / "recon/ffuf.sh"
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Subprocess environment
SUBPROC_ENV = {
    **os.environ,
    "HOME": "/home/ubuntu",
    "PATH": "/snap/bin:/home/ubuntu/go/bin:/home/ubuntu/.local/bin:/usr/local/bin:/usr/bin:/bin",
}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("recon-bot")

RUNNING_JOBS = {}

# =====================================================
# HELPERS
# =====================================================

def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.split("/")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def format_time(seconds: int) -> str:
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"

# =====================================================
# TELETHON
# =====================================================

telethon_client = TelegramClient(
    SESSION_NAME,
    API_ID,
    API_HASH,
    sequential_updates=True,
)

UPLOAD_LOCK = asyncio.Semaphore(1)

async def init_telethon():
    if not telethon_client.is_connected():
        await telethon_client.start()
        logger.info("Telethon connected")

async def upload_large_file(path: Path) -> str:
    async with UPLOAD_LOCK:
        msg = await telethon_client.send_file(
            CHANNEL_ID,
            path,
            caption=path.name,
        )
        return f"https://t.me/c/{str(CHANNEL_ID)[4:]}/{msg.id}"

# =====================================================
# COMMANDS
# =====================================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Recon Bot Online\n\n"
        "/recon <domain>\n"
        "/ffuf <domain> [options]\n"
        "/status <job_id>\n"
        "/cancel <job_id>"
    )

# =====================================================
# RECON
# =====================================================

async def recon(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ALLOWED_USER_ID:
        return await update.message.reply_text("Not allowed")

    if not context.args:
        return await update.message.reply_text("Usage: /recon <domain>")

    raw_domain = context.args[0]
    domain = normalize_domain(raw_domain)
    extra_args = context.args[1:]

    job_id = uuid.uuid4().hex[:8]
    start_time = time.time()

    RUNNING_JOBS[job_id] = {
        "domain": domain,
        "start": start_time,
        "status": "running",
        "proc": None,
        "type": "recon",
    }

    await update.message.reply_text(
        f"Recon started\n\nDomain: {domain}\nJob ID: {job_id}"
    )

    async def run_recon():
        domain_dir = OUTPUT_DIR / domain
        domain_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            "/usr/bin/env",
            "bash",
            str(RECON_SCRIPT),
            domain,
            *extra_args,
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(BASE_DIR),
            env=SUBPROC_ENV,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        RUNNING_JOBS[job_id]["proc"] = proc

        await proc.wait()
        RUNNING_JOBS[job_id]["status"] = "finished"

        zip_path = OUTPUT_DIR / f"{domain}_{job_id}.zip"
        shutil.make_archive(
            str(zip_path).replace(".zip", ""),
            "zip",
            domain_dir,
        )

        elapsed = int(time.time() - start_time)
        size_mb = zip_path.stat().st_size / (1024 * 1024)

        link = await upload_large_file(zip_path)

        await update.message.reply_text(
            f"Recon completed\n\n"
            f"Job: {job_id}\n"
            f"Time: {format_time(elapsed)}\n"
            f"Size: {size_mb:.2f} MB\n\n"
            f"Download:\n{link}"
        )

        RUNNING_JOBS.pop(job_id, None)

    asyncio.create_task(run_recon())

# =====================================================
# FFUF (FIXED)
# =====================================================

async def ffuf(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ALLOWED_USER_ID:
        return await update.message.reply_text("Not allowed")

    if not context.args:
        return await update.message.reply_text("Usage: /ffuf <domain> [options]")

    raw_domain = context.args[0]
    domain = normalize_domain(raw_domain)
    extra_args = context.args[1:]

    domain_dir = OUTPUT_DIR / domain
    httpx_file = domain_dir / "http_discovery" / "httpx_full.txt"

    if not httpx_file.exists():
        return await update.message.reply_text(
            f"httpx_full.txt not found for `{domain}`\n\n"
            f"Expected:\n{httpx_file}\n\n"
            "Run /recon first.",
            parse_mode="Markdown"
        )

    job_id = uuid.uuid4().hex[:8]
    start_time = time.time()

    RUNNING_JOBS[job_id] = {
        "domain": domain,
        "start": start_time,
        "status": "running",
        "proc": None,
        "type": "ffuf",
    }

    await update.message.reply_text(
        f"FFUF started\n\nDomain: {domain}\nJob ID: {job_id}"
    )

    async def run_ffuf():
        ffuf_output_dir = domain_dir / "ffuf-results"
        ffuf_output_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            "/usr/bin/env",
            "bash",
            str(FFUF_SCRIPT),
            str(httpx_file),
            *extra_args,
            "-o", str(ffuf_output_dir),
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(BASE_DIR),
            env=SUBPROC_ENV,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        RUNNING_JOBS[job_id]["proc"] = proc
        await proc.wait()

        zip_path = OUTPUT_DIR / f"{domain}_ffuf_{job_id}.zip"

        if any(ffuf_output_dir.iterdir()):
            shutil.make_archive(
                str(zip_path).replace(".zip", ""),
                "zip",
                ffuf_output_dir,
            )

            elapsed = int(time.time() - start_time)
            size_mb = zip_path.stat().st_size / (1024 * 1024)
            link = await upload_large_file(zip_path)

            await update.message.reply_text(
                f"FFUF completed\n\n"
                f"Job: {job_id}\n"
                f"Time: {format_time(elapsed)}\n"
                f"Size: {size_mb:.2f} MB\n\n"
                f"Download:\n{link}"
            )
        else:
            await update.message.reply_text("FFUF completed — no findings.")

        RUNNING_JOBS.pop(job_id, None)

    asyncio.create_task(run_ffuf())

# =====================================================
# STATUS / CANCEL
# =====================================================

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        return await update.message.reply_text("Usage: /status <job_id>")

    job = RUNNING_JOBS.get(context.args[0])
    if not job:
        return await update.message.reply_text("Job not found")

    elapsed = int(time.time() - job["start"])

    await update.message.reply_text(
        f"Job: {context.args[0]}\n"
        f"Type: {job['type']}\n"
        f"Domain: {job['domain']}\n"
        f"Status: {job['status']}\n"
        f"Elapsed: {format_time(elapsed)}"
    )

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ALLOWED_USER_ID:
        return await update.message.reply_text("Not allowed")

    if not context.args:
        return await update.message.reply_text("Usage: /cancel <job_id>")

    job = RUNNING_JOBS.get(context.args[0])
    if not job:
        return await update.message.reply_text("Job not found")

    proc = job.get("proc")
    if proc and proc.returncode is None:
        proc.kill()
        job["status"] = "cancelled"
        await update.message.reply_text("Job cancelled")

# =====================================================
# MAIN
# =====================================================

async def post_init(app):
    await init_telethon()

def main():
    app = (
        ApplicationBuilder()
        .token(BOT_TOKEN)
        .post_init(post_init)
        .build()
    )

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("recon", recon))
    app.add_handler(CommandHandler("ffuf", ffuf))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("cancel", cancel))

    logger.info("Recon Bot started")
    app.run_polling()

if __name__ == "__main__":
    main()
