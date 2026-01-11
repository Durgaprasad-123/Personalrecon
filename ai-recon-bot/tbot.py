import asyncio
import subprocess
import os
import time
import shutil
import uuid
import logging
import re
from pathlib import Path
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes
)

# =========================
# CONFIG
# =========================
TOKEN = "xxxxxxxxxxxxxxxxxxxxxxxxxx"
ALLOWED_USER_ID = xxxxxxxxx  # your Telegram numeric ID

BASE_DIR = Path("/home/ubuntu/ai-recon-bot")
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

RECON_SCRIPT = BASE_DIR / "recon" / "recon.sh"

MAX_RUNTIME = 48 * 3600
PHASE_STALL_LIMIT = 90 * 60

SUBPROC_ENV = {
    **os.environ,
    "HOME": "/home/ubuntu",
    "PATH": "/snap/bin:/home/ubuntu/go/bin:/home/ubuntu/.local/bin:/usr/local/bin:/usr/bin:/bin"
}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("telegram-bot")

RUNNING_JOBS = {}

# Stage emojis for better visualization
STAGE_EMOJIS = {
    "starting": "🔄",
    "passive": "🔍",
    "bruteforce": "💥",
    "permutations": "🔀",
    "dns": "🌐",
    "recon_intel": "🧠",
    "http_discovery": "🔎",
    "http_exploitation": "🎯",
    "nuclei": "💣",
    "ffuf": "📁",
    "cleanup": "🧹",
    "done": "✅"
}

# =========================
# HELPERS
# =========================
def safe_domain(d: str) -> str:
    return "".join(c for c in d if c.isalnum() or c in "-.")

def parse_stage_from_log(line: str) -> str:
    """Extract stage name from recon.sh log output"""
    # Match patterns like: "[*] 2025-01-11 12:34:56 :: STAGE: passive"
    stage_match = re.search(r'STAGE:\s*(\w+)', line, re.IGNORECASE)
    if stage_match:
        return stage_match.group(1).lower()
    
    # Match patterns like: "[*] Running subfinder..."
    if "running subfinder" in line.lower() or "running assetfinder" in line.lower():
        return "passive"
    elif "running amass" in line.lower():
        return "passive"
    elif "bruteforce dns" in line.lower() or "puredns bruteforce" in line.lower():
        return "bruteforce"
    elif "running dnsgen" in line.lower() or "running altdns" in line.lower():
        return "permutations"
    elif "resolve" in line.lower() and "candidates" in line.lower():
        return "dns"
    elif "cloud assets" in line.lower() or "takeover" in line.lower():
        return "recon_intel"
    elif "running httpx" in line.lower() or "http discovery" in line.lower():
        return "http_discovery"
    elif "high-value" in line.lower():
        return "http_exploitation"
    elif "nuclei" in line.lower() and ("scanning" in line.lower() or "templates" in line.lower()):
        return "nuclei"
    elif "ffuf" in line.lower() or "directory fuzzing" in line.lower():
        return "ffuf"
    elif "cleaning up" in line.lower() or "cleanup" in line.lower():
        return "cleanup"
    elif "recon completed" in line.lower() or "finished" in line.lower():
        return "done"
    
    return None

def get_stage_emoji(stage: str) -> str:
    """Get emoji for stage"""
    return STAGE_EMOJIS.get(stage, "⚙️")

def format_time(seconds: int) -> str:
    """Format seconds into human-readable time"""
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    
    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    elif minutes > 0:
        return f"{minutes}m {secs}s"
    else:
        return f"{secs}s"

# =========================
# COMMANDS
# =========================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🤖 *Advanced Recon Bot Online*\n\n"
        "*Available Commands:*\n"
        "📍 `/recon <domain>` - Start full reconnaissance\n"
        "📍 `/recon <domain> --from <stage>` - Start from specific stage\n"
        "📊 `/status <job_id>` - Check job status and current stage\n"
        "🛑 `/cancel <job_id>` - Cancel running job\n"
        "📋 `/jobs` - List all running jobs\n"
        "💻 `/sh <cmd>` - Execute shell command\n\n"
        "*Reconnaissance Stages:*\n"
        "🔍 passive → 💥 bruteforce → 🔀 permutations → 🌐 dns\n"
        "🧠 recon_intel → 🔎 http_discovery → 🎯 http_exploitation\n"
        "💣 nuclei → 📁 ffuf → 🧹 cleanup → ✅ done\n\n"
        "*Examples:*\n"
        "`/recon example.com`\n"
        "`/recon example.com --from nuclei`\n"
        "`/status a1b2c3d4`",
        parse_mode='Markdown'
    )

# -------------------------
# RECON
# -------------------------
async def recon(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ALLOWED_USER_ID:
        return await update.message.reply_text("❌ Not allowed")

    if not context.args:
        return await update.message.reply_text(
            "❌ *Usage:*\n"
            "`/recon example.com`\n"
            "`/recon example.com --from nuclei`",
            parse_mode='Markdown'
        )

    domain = safe_domain(context.args[0])
    extra_args = context.args[1:]

    job_id = uuid.uuid4().hex[:8]
    
    # Build command description
    cmd_desc = f"full scan"
    if "--from" in extra_args:
        try:
            stage_idx = extra_args.index("--from")
            start_stage = extra_args[stage_idx + 1]
            cmd_desc = f"from stage: {start_stage}"
        except:
            pass
    
    await update.message.reply_text(
        f"🚀 *Recon Started*\n\n"
        f"🎯 Domain: `{domain}`\n"
        f"🆔 Job ID: `{job_id}`\n"
        f"⚙️ Mode: {cmd_desc}\n\n"
        f"Use `/status {job_id}` to track progress",
        parse_mode='Markdown'
    )

    RUNNING_JOBS[job_id] = {
        "domain": domain,
        "start": time.time(),
        "last_phase_change": time.time(),
        "stage": "starting",
        "status": "running",
        "proc": None,
        "last_output": "",
        "stats": {
            "passive_seeds": 0,
            "resolved_domains": 0,
            "live_urls": 0,
            "findings": 0,
            "ffuf_paths": 0
        }
    }

    async def run():
        domain_dir = OUTPUT_DIR / domain
        domain_dir.mkdir(parents=True, exist_ok=True)

        cmd = [str(RECON_SCRIPT), domain] + extra_args

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(BASE_DIR),
            env=SUBPROC_ENV,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        RUNNING_JOBS[job_id]["proc"] = proc

        async def watchdog():
            """Monitor for timeouts and stalls"""
            while proc.returncode is None:
                await asyncio.sleep(30)
                now = time.time()
                job = RUNNING_JOBS.get(job_id)
                if not job:
                    return

                # Global timeout
                if now - job["start"] > MAX_RUNTIME:
                    logger.warning(f"[{job_id}] Global timeout reached")
                    proc.kill()
                    job["status"] = "killed (global timeout)"
                    await update.message.reply_text(
                        f"⏱️ Job `{job_id}` killed: global timeout ({MAX_RUNTIME}s)",
                        parse_mode='Markdown'
                    )
                    return

                # Stage stall detection
                stall_time = now - job["last_phase_change"]
                if stall_time > PHASE_STALL_LIMIT:
                    logger.warning(f"[{job_id}] Stage stall detected ({stall_time}s)")
                    proc.kill()
                    job["status"] = "killed (stalled)"
                    await update.message.reply_text(
                        f"⏱️ Job `{job_id}` killed: stage `{job['stage']}` stalled for {int(stall_time)}s",
                        parse_mode='Markdown'
                    )
                    return

        watchdog_task = asyncio.create_task(watchdog())

        try:
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break

                text = line.decode(errors="ignore").strip()
                if not text:
                    continue

                logger.info(f"[{job_id}] {text}")
                RUNNING_JOBS[job_id]["last_output"] = text

                # Detect stage changes
                detected_stage = parse_stage_from_log(text)
                if detected_stage:
                    old_stage = RUNNING_JOBS[job_id]["stage"]
                    if detected_stage != old_stage:
                        RUNNING_JOBS[job_id]["stage"] = detected_stage
                        RUNNING_JOBS[job_id]["last_phase_change"] = time.time()
                        
                        emoji = get_stage_emoji(detected_stage)
                        logger.info(f"[{job_id}] Stage changed: {old_stage} → {detected_stage}")
                        
                        # Send stage change notification
                        await update.message.reply_text(
                            f"{emoji} Job `{job_id}` → Stage: *{detected_stage}*",
                            parse_mode='Markdown'
                        )

                # Extract statistics from log
                if "passive seeds:" in text.lower():
                    match = re.search(r'(\d+)', text)
                    if match:
                        RUNNING_JOBS[job_id]["stats"]["passive_seeds"] = int(match.group(1))
                
                elif "resolved domains:" in text.lower():
                    match = re.search(r'(\d+)', text)
                    if match:
                        RUNNING_JOBS[job_id]["stats"]["resolved_domains"] = int(match.group(1))
                
                elif "live http services:" in text.lower() or "live urls:" in text.lower():
                    match = re.search(r'(\d+)', text)
                    if match:
                        RUNNING_JOBS[job_id]["stats"]["live_urls"] = int(match.group(1))
                
                elif "critical" in text.lower() and "findings:" in text.lower():
                    match = re.search(r'(\d+)', text)
                    if match:
                        RUNNING_JOBS[job_id]["stats"]["findings"] = int(match.group(1))
                
                elif "ffuf" in text.lower() and ("found" in text.lower() or "findings:" in text.lower()):
                    match = re.search(r'(\d+)', text)
                    if match:
                        RUNNING_JOBS[job_id]["stats"]["ffuf_paths"] = int(match.group(1))

            await proc.wait()

            RUNNING_JOBS[job_id]["status"] = "finished"
            RUNNING_JOBS[job_id]["stage"] = "done"

            # Analyze results before zipping
            elapsed = int(time.time() - RUNNING_JOBS[job_id]["start"])
            stats = RUNNING_JOBS[job_id]["stats"]
            
            # Check ffuf results
            ffuf_summary = ""
            ffuf_findings_file = domain_dir / "ffuf" / "ALL_FINDINGS.txt"
            ffuf_high_value_file = domain_dir / "ffuf" / "HIGH_VALUE_FINDINGS.txt"
            
            if ffuf_findings_file.exists():
                ffuf_total = sum(1 for _ in open(ffuf_findings_file))
                stats['ffuf_paths'] = ffuf_total
                ffuf_summary += f"└ ffuf Paths: {ffuf_total}\n"
                
                if ffuf_high_value_file.exists():
                    ffuf_high = sum(1 for _ in open(ffuf_high_value_file))
                    ffuf_summary += f"└ High-Value: {ffuf_high}\n"
            
            # Check nuclei critical findings
            nuclei_critical_file = domain_dir / "nuclei" / "CRITICAL_FINDINGS.txt"
            if nuclei_critical_file.exists():
                critical_count = sum(1 for _ in open(nuclei_critical_file))
                if critical_count > 0:
                    stats['findings'] = critical_count
            
            # Send summary
            summary_msg = (
                f"✅ *Recon Completed*\n\n"
                f"🎯 Domain: `{domain}`\n"
                f"🆔 Job ID: `{job_id}`\n"
                f"⏱️ Time: {format_time(elapsed)}\n\n"
                f"📊 *Results:*\n"
                f"└ Subdomains: {stats.get('resolved_domains', 0)}\n"
                f"└ Live URLs: {stats.get('live_urls', 0)}\n"
            )
            
            if ffuf_summary:
                summary_msg += ffuf_summary
            
            if stats.get('findings', 0) > 0:
                summary_msg += f"└ 🚨 Critical Findings: {stats['findings']}\n"
            
            summary_msg += f"\n📦 Creating archive..."
            
            await update.message.reply_text(summary_msg, parse_mode='Markdown')
            
            # Create ZIP archive
            zip_path = OUTPUT_DIR / f"{domain}_{job_id}.zip"
            if zip_path.exists():
                zip_path.unlink()

            shutil.make_archive(
                str(zip_path).replace(".zip", ""),
                "zip",
                domain_dir
            )
            
            # Send ZIP file with detailed caption
            if zip_path.exists():
                zip_size = zip_path.stat().st_size / (1024 * 1024)  # MB
                
                caption = (
                    f"📦 *Results for {domain}*\n\n"
                    f"🆔 Job: `{job_id}`\n"
                    f"📏 Size: {zip_size:.2f} MB\n\n"
                    f"📂 *Contents:*\n"
                    f"└ dns/resolved_domains.txt\n"
                    f"└ http_discovery/live_urls.txt\n"
                    f"└ nuclei/CRITICAL_FINDINGS.txt\n"
                    f"└ ffuf/ALL_FINDINGS.txt\n"
                    f"└ logs/recon.log"
                )
                
                await update.message.reply_document(
                    zip_path.open("rb"),
                    caption=caption,
                    parse_mode='Markdown'
                )
                
                # Send quick preview of critical findings if any
                if stats.get('findings', 0) > 0 and nuclei_critical_file.exists():
                    preview = []
                    with open(nuclei_critical_file, 'r') as f:
                        for i, line in enumerate(f):
                            if i >= 10:  # Only first 10 findings
                                break
                            preview.append(line.strip())
                    
                    if preview:
                        preview_msg = "🚨 *Critical Findings Preview:*\n\n"
                        preview_msg += "```\n" + "\n".join(preview) + "\n```"
                        if stats['findings'] > 10:
                            preview_msg += f"\n\n_...and {stats['findings'] - 10} more (see ZIP file)_"
                        
                        await update.message.reply_text(preview_msg, parse_mode='Markdown')
                
                # Send ffuf high-value preview if exists
                if ffuf_high_value_file.exists():
                    ffuf_preview = []
                    with open(ffuf_high_value_file, 'r') as f:
                        for i, line in enumerate(f):
                            if i >= 15:  # First 15 paths
                                break
                            ffuf_preview.append(line.strip())
                    
                    if ffuf_preview:
                        ffuf_msg = "📁 *ffuf High-Value Paths:*\n\n"
                        ffuf_msg += "```\n" + "\n".join(ffuf_preview) + "\n```"
                        
                        ffuf_total = stats.get('ffuf_paths', 0)
                        if ffuf_total > 15:
                            ffuf_msg += f"\n\n_...and {ffuf_total - 15} more (see ZIP file)_"
                        
                        await update.message.reply_text(ffuf_msg, parse_mode='Markdown')

        except Exception as e:
            logger.error(f"[{job_id}] Error: {e}")
            RUNNING_JOBS[job_id]["status"] = "error"
            await update.message.reply_text(
                f"❌ Job `{job_id}` failed: {str(e)}",
                parse_mode='Markdown'
            )
        
        finally:
            watchdog_task.cancel()
            # Keep job in history for 1 hour for status checks
            await asyncio.sleep(3600)
            RUNNING_JOBS.pop(job_id, None)

    asyncio.create_task(run())

# -------------------------
# STATUS
# -------------------------
async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        return await update.message.reply_text(
            "❌ *Usage:*\n`/status <job_id>`\n\n"
            "Use `/jobs` to see running jobs",
            parse_mode='Markdown'
        )

    job_id = context.args[0]
    job = RUNNING_JOBS.get(job_id)
    
    if not job:
        return await update.message.reply_text(
            f"❌ Job `{job_id}` not found\n\n"
            f"Use `/jobs` to see running jobs",
            parse_mode='Markdown'
        )

    elapsed = int(time.time() - job["start"])
    stall = int(time.time() - job["last_phase_change"])
    
    stage = job["stage"]
    emoji = get_stage_emoji(stage)
    stats = job["stats"]
    
    # Build status message
    status_msg = f"📊 *Job Status*\n\n"
    status_msg += f"🆔 ID: `{job_id}`\n"
    status_msg += f"🎯 Domain: `{job['domain']}`\n"
    status_msg += f"{emoji} Stage: *{stage}*\n"
    status_msg += f"🔄 Status: `{job['status']}`\n"
    status_msg += f"⏱️ Elapsed: {format_time(elapsed)}\n"
    status_msg += f"⏸️ Stage Time: {format_time(stall)}\n\n"
    
    # Add statistics if available
    if any(stats.values()):
        status_msg += f"📈 *Progress:*\n"
        if stats['passive_seeds'] > 0:
            status_msg += f"└ Passive Seeds: {stats['passive_seeds']}\n"
        if stats['resolved_domains'] > 0:
            status_msg += f"└ Resolved Domains: {stats['resolved_domains']}\n"
        if stats['live_urls'] > 0:
            status_msg += f"└ Live URLs: {stats['live_urls']}\n"
        if stats['findings'] > 0:
            status_msg += f"└ Findings: {stats['findings']}\n"
        status_msg += "\n"
    
    # Add last output
    if job["last_output"]:
        last_out = job["last_output"][:200]
        status_msg += f"📝 *Last Output:*\n`{last_out}`"
    
    await update.message.reply_text(status_msg, parse_mode='Markdown')

# -------------------------
# JOB LIST
# -------------------------
async def jobs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not RUNNING_JOBS:
        return await update.message.reply_text(
            "📭 No running jobs\n\n"
            "Use `/recon <domain>` to start a scan",
            parse_mode='Markdown'
        )

    msg = "📋 *Running Jobs:*\n\n"
    
    for jid, job in RUNNING_JOBS.items():
        emoji = get_stage_emoji(job['stage'])
        elapsed = int(time.time() - job["start"])
        
        msg += f"🆔 `{jid}`\n"
        msg += f"└ Domain: `{job['domain']}`\n"
        msg += f"└ {emoji} Stage: *{job['stage']}*\n"
        msg += f"└ Time: {format_time(elapsed)}\n\n"

    msg += f"Use `/status <job_id>` for details"
    await update.message.reply_text(msg, parse_mode='Markdown')

# -------------------------
# CANCEL
# -------------------------
async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ALLOWED_USER_ID:
        return await update.message.reply_text("❌ Not allowed")

    if not context.args:
        return await update.message.reply_text(
            "❌ *Usage:*\n`/cancel <job_id>`",
            parse_mode='Markdown'
        )

    job_id = context.args[0]
    job = RUNNING_JOBS.get(job_id)
    
    if not job:
        return await update.message.reply_text(
            f"❌ Job `{job_id}` not found",
            parse_mode='Markdown'
        )

    proc = job.get("proc")
    if proc and proc.returncode is None:
        proc.kill()
        job["status"] = "cancelled"
        
        await update.message.reply_text(
            f"🛑 *Job Cancelled*\n\n"
            f"🆔 ID: `{job_id}`\n"
            f"🎯 Domain: `{job['domain']}`\n"
            f"📍 Was at stage: *{job['stage']}*",
            parse_mode='Markdown'
        )
    else:
        await update.message.reply_text(
            f"❌ Job `{job_id}` is not running",
            parse_mode='Markdown'
        )

# -------------------------
# SHELL
# -------------------------
async def shell(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ALLOWED_USER_ID:
        return await update.message.reply_text("❌ Not allowed")

    if not context.args:
        return await update.message.reply_text(
            "❌ *Usage:*\n`/sh <command>`",
            parse_mode='Markdown'
        )

    cmd = " ".join(context.args)
    
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            executable="/bin/bash",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30
        )

        out = proc.stdout
        if proc.stderr:
            out += f"\n\n[STDERR]\n{proc.stderr}"
        
        if not out:
            out = "[No output]"
        
        if len(out) < 3800:
            await update.message.reply_text(
                f"💻 *Command:* `{cmd}`\n\n```\n{out}\n```",
                parse_mode='Markdown'
            )
        else:
            f = OUTPUT_DIR / f"sh_{uuid.uuid4().hex}.txt"
            f.write_text(out)
            await update.message.reply_document(
                f.open("rb"),
                caption=f"Output of: {cmd}"
            )
            f.unlink()
    
    except subprocess.TimeoutExpired:
        await update.message.reply_text(
            f"⏱️ Command timed out after 30s",
            parse_mode='Markdown'
        )
    except Exception as e:
        await update.message.reply_text(
            f"❌ Error: `{str(e)}`",
            parse_mode='Markdown'
        )

# =========================
# MAIN
# =========================
def main():
    app = ApplicationBuilder().token(TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("recon", recon))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("jobs", jobs))
    app.add_handler(CommandHandler("cancel", cancel))
    app.add_handler(CommandHandler("sh", shell))

    logger.info("🤖 Telegram Recon Bot started")
    app.run_polling()

if __name__ == "__main__":
    main()                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 



