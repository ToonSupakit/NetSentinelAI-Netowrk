import discord
import yaml
import asyncio
import logging
import os
from datetime import datetime
from app.db import get_anomaly_history, get_device_status, mark_as_fixed, get_analytics
from app.runtime import shutdown_event
from app.vendor_adapters import remediation_commands
from netmiko import ConnectHandler
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger(__name__)

with open("config/config.yaml", "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

with open("config/devices.yaml", "r", encoding="utf-8") as f:
    devices_config = yaml.safe_load(f)

# Discord Token
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
DISCORD_CHANNEL_ID = os.getenv("DISCORD_CHANNEL_ID", config.get("discord", {}).get("channel_id"))

if DISCORD_CHANNEL_ID:
    DISCORD_CHANNEL_ID = int(DISCORD_CHANNEL_ID)

intents = discord.Intents.default()
intents.message_content = True
intents.messages = True
client = discord.Client(intents=intents)

anomaly_queue = asyncio.Queue()
THRESHOLD_LOAD = config.get("model", {}).get("threshold_load", 20)


# ── ดึง credentials ของ device ──────────────────────────────────────
def get_device_conn_params(device):
    return {
        "device_type": device["device_type"],
        "host": device["host"],
        "username": device.get("username") or os.getenv("DEVICE_USERNAME", "admin"),
        "password": device.get("password") or os.getenv("DEVICE_PASSWORD", "admin"),
        "secret": device.get("secret") or os.getenv("DEVICE_SECRET", "admin"),
    }


def _format_detection_source(src: str) -> str:
    """แปลงค่า detection_source เป็นข้อความสั้นๆ ใน embed"""
    labels = {
        "device_unreachable": "Device unreachable",
        "rules": "Rule-based thresholds",
        "rules+ai": "Rules + ML",
        "ai": "ML (Isolation Forest)",
        "isolation_forest": "ML (Isolation Forest)",
        "no_model": "N/A (no model file)",
        "healthy": "Normal",
    }
    return labels.get(src, src)


async def send_timeout_alert(info):
    if not DISCORD_CHANNEL_ID:
        return
    channel = client.get_channel(DISCORD_CHANNEL_ID)
    if not channel:
        return

    embed = discord.Embed(title="⚠️ Device Timeout!", color=discord.Color.orange(), timestamp=datetime.now())
    embed.add_field(name="Device", value=info["device"], inline=True)
    embed.add_field(name="Host", value=info["host"], inline=True)
    embed.add_field(name="Zone", value=info["zone"], inline=True)
    embed.add_field(name="Error", value=info["error"][:200], inline=False)
    embed.set_footer(text="Python ไม่สามารถเชื่อมต่อได้ กรุณาตรวจสอบ device")
    await channel.send(embed=embed)


def get_device_by_name(name):
    for d in devices_config["devices"]:
        if d["name"] == name:
            return d
    return None


async def send_anomaly_alert(anomaly):
    if not DISCORD_CHANNEL_ID:
        return
    channel = client.get_channel(DISCORD_CHANNEL_ID)
    if not channel:
        return

    causes_text = "\n".join([f"• {c}" for c in anomaly["causes"]])
    suggestions_text = "\n".join([f"• {s}" for s in anomaly["suggestions"]])

    embed = discord.Embed(title="🚨 ANOMALY DETECTED!", color=discord.Color.red(), timestamp=datetime.now())
    embed.add_field(name="Device", value=anomaly["device"], inline=True)
    intf_val = f"{anomaly['intf']} ({anomaly.get('ip', 'N/A')})" if anomaly["intf"] != "ALL" else f"Device Level ({anomaly.get('ip', 'N/A')})"
    embed.add_field(name="Interface", value=intf_val, inline=True)
    embed.add_field(name="Link Type", value=anomaly["link_type"], inline=True)
    embed.add_field(name="Severity", value=str(anomaly.get("severity", "unknown")).upper(), inline=True)
    embed.add_field(name="Confidence", value=f"{anomaly['confidence']:.0%}", inline=True)
    src = anomaly.get("detection_source")
    if src:
        embed.add_field(
            name="Detection",
            value=_format_detection_source(src),
            inline=True,
        )
    embed.add_field(name="Status", value="up" if anomaly["status_num"] else "down", inline=True)
    embed.add_field(name="Protocol", value="up" if anomaly["protocol_num"] else "down", inline=True)
    embed.add_field(
        name="TX Load",
        value=f"{anomaly['network_load']}/255 ({round(anomaly['network_load']/255*100,1)}%)",
        inline=True,
    )
    embed.add_field(
        name="RX Load", value=f"{anomaly['rxload']}/255 ({round(anomaly['rxload']/255*100,1)}%)", inline=True
    )
    embed.add_field(name="Reliability", value=f"{anomaly['reliability']}/255", inline=True)
    embed.add_field(name="🔎 สาเหตุ", value=causes_text or "ไม่ทราบสาเหตุ", inline=False)
    embed.add_field(name="💡 คำแนะนำ", value=suggestions_text or "-", inline=False)

    view = AnomalyView(anomaly)
    await channel.send(embed=embed, view=view)


class AnomalyView(discord.ui.View):
    def __init__(self, anomaly):
        super().__init__(timeout=300)
        self.anomaly = anomaly

    async def _check_admin(self, interaction: discord.Interaction):
        # ตรวจสอบสิทธิ์ว่าผู้ใช้เป็น Administrator ในเซิร์ฟเวอร์หรือไม่
        if not interaction.user.guild_permissions.administrator:
            await interaction.response.send_message(
                "⛔ **Access Denied**: เฉพาะผู้ดูแลระบบ (Administrator) เท่านั้นที่มีสิทธิ์กดปุ่มนี้!", ephemeral=True
            )
            return False
        return True

    @discord.ui.button(label="✅ Approve Fix", style=discord.ButtonStyle.success)
    async def fix_now(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not await self._check_admin(interaction):
            return
        await interaction.response.defer()
        device = get_device_by_name(self.anomaly["device"])
        if not device:
            await interaction.followup.send("❌ ไม่พบข้อมูล device")
            return
        intf_suffix = f" - {self.anomaly['intf']}" if self.anomaly['intf'] != "ALL" else ""
        await interaction.followup.send(f"⏳ กำลัง fix {self.anomaly['device']}{intf_suffix}...")
        try:
            conn_params = get_device_conn_params(device)
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, lambda: fix_interface(conn_params, self.anomaly["intf"]))
            mark_as_fixed(self.anomaly["log_id"])
            embed = discord.Embed(title="✅ Fix สำเร็จ!", color=discord.Color.green(), timestamp=datetime.now())
            embed.add_field(name="Device", value=self.anomaly["device"], inline=True)
            if self.anomaly["intf"] != "ALL":
                embed.add_field(name="Interface", value=self.anomaly["intf"], inline=True)
            embed.add_field(name="Action", value="no shutdown", inline=True)
            embed.add_field(name="Result", value=result[:500], inline=False)
            await interaction.followup.send(embed=embed)
            button.disabled = True
            await interaction.message.edit(view=self)
            log.info(f"Discord Bot fix_now success: {self.anomaly['device']}{intf_suffix}")
        except Exception as e:
            await interaction.followup.send(f"❌ Fix ไม่สำเร็จ: {e}")
            log.error(f"Discord Bot fix_now failed: {e}")

    @discord.ui.button(label="📊 Check Status", style=discord.ButtonStyle.primary)
    async def check_status(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer()
        device = get_device_by_name(self.anomaly["device"])
        if not device:
            await interaction.followup.send("❌ ไม่พบข้อมูล device")
            return
        try:
            conn_params = get_device_conn_params(device)
            loop = asyncio.get_event_loop()
            status = await loop.run_in_executor(None, lambda: check_interface_status(conn_params, self.anomaly["intf"]))
            title_val = f"📊 Status: {self.anomaly['device']}" if self.anomaly['intf'] == "ALL" else f"📊 Status: {self.anomaly['device']} - {self.anomaly['intf']}"
            embed = discord.Embed(
                title=title_val,
                color=discord.Color.blue(),
                timestamp=datetime.now(),
            )
            embed.add_field(name="Current Status", value=status, inline=False)
            await interaction.followup.send(embed=embed)
        except Exception as e:
            await interaction.followup.send(f"❌ Check status ไม่สำเร็จ: {e}")

    @discord.ui.button(label="🚦 Rate Limit", style=discord.ButtonStyle.primary)
    async def rate_limit(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not await self._check_admin(interaction):
            return
        await interaction.response.defer()
        if self.anomaly["network_load"] <= THRESHOLD_LOAD and self.anomaly["rxload"] <= THRESHOLD_LOAD:
            await interaction.followup.send("ℹ️ Anomaly นี้ไม่ใช่ High Traffic ไม่จำเป็นต้อง Rate Limit")
            return
        device = get_device_by_name(self.anomaly["device"])
        if not device:
            await interaction.followup.send("❌ ไม่พบข้อมูล device")
            return
        intf_suffix = f" - {self.anomaly['intf']}" if self.anomaly['intf'] != "ALL" else ""
        await interaction.followup.send(f"⏳ กำลัง Rate Limit {self.anomaly['device']}{intf_suffix}...")
        try:
            conn_params = get_device_conn_params(device)
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, lambda: apply_rate_limit(conn_params, self.anomaly["intf"]))
            embed = discord.Embed(
                title="🚦 Rate Limit Applied!", color=discord.Color.yellow(), timestamp=datetime.now()
            )
            embed.add_field(name="Device", value=self.anomaly["device"], inline=True)
            if self.anomaly["intf"] != "ALL":
                embed.add_field(name="Interface", value=self.anomaly["intf"], inline=True)
            embed.add_field(name="Action", value="Rate Limit 50Mbps", inline=True)
            embed.add_field(name="Result", value=result[:500], inline=False)
            embed.set_footer(text="⚠️ Rate limit นี้เป็นแค่ชั่วคราว ควรหาสาเหตุที่แท้จริงด้วย")
            await interaction.followup.send(embed=embed)
            button.disabled = True
            await interaction.message.edit(view=self)
            log.info(f"Discord Bot rate_limit success: {self.anomaly['device']}{intf_suffix}")
        except Exception as e:
            await interaction.followup.send(f"❌ Rate Limit ไม่สำเร็จ: {e}")
            log.error(f"Discord Bot rate_limit failed: {e}")

    @discord.ui.button(label="🔓 Remove Limit", style=discord.ButtonStyle.secondary)
    async def remove_rate_limit(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not await self._check_admin(interaction):
            return
        await interaction.response.defer()
        device = get_device_by_name(self.anomaly["device"])
        if not device:
            await interaction.followup.send("❌ ไม่พบข้อมูล device")
            return
        try:
            conn_params = get_device_conn_params(device)
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, lambda: remove_rate_limit_router(conn_params, self.anomaly["intf"])
            )
            embed = discord.Embed(title="🔓 Rate Limit Removed!", color=discord.Color.green(), timestamp=datetime.now())
            embed.add_field(name="Device", value=self.anomaly["device"], inline=True)
            if self.anomaly["intf"] != "ALL":
                embed.add_field(name="Interface", value=self.anomaly["intf"], inline=True)
            embed.add_field(name="Result", value=result[:500], inline=False)
            await interaction.followup.send(embed=embed)
            button.disabled = True
            await interaction.message.edit(view=self)
            intf_suffix = f" - {self.anomaly['intf']}" if self.anomaly['intf'] != "ALL" else ""
            log.info(f"Discord Bot remove_rate_limit success: {self.anomaly['device']}{intf_suffix}")
        except Exception as e:
            await interaction.followup.send(f"❌ Remove Rate Limit ไม่สำเร็จ: {e}")
            log.error(f"Discord Bot remove_rate_limit failed: {e}")

    @discord.ui.button(label="❌ Ignore", style=discord.ButtonStyle.secondary)
    async def ignore(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not await self._check_admin(interaction):
            return
        intf_suffix = f" - {self.anomaly['intf']}" if self.anomaly['intf'] != "ALL" else ""
        await interaction.response.send_message(f"⏭️ Ignored: {self.anomaly['device']}{intf_suffix}")
        for child in self.children:
            child.disabled = True
        await interaction.message.edit(view=self)


def _send_remediation(conn_params, intf, action, limit_mbps=None):
    cmds = remediation_commands(conn_params.get("device_type"), intf, action, limit_mbps=limit_mbps)
    if not cmds:
        raise ValueError(f"Action {action} is not supported for {conn_params.get('device_type')}")
    with ConnectHandler(**conn_params) as net:
        if "cisco" in conn_params.get("device_type", "") or "arista" in conn_params.get("device_type", ""):
            net.enable()
        output = net.send_config_set(cmds)
        return output


def fix_interface(conn_params, intf):
    return _send_remediation(conn_params, intf, "fix")


def check_interface_status(conn_params, intf):
    with ConnectHandler(**conn_params) as net:
        if "cisco" in conn_params.get("device_type", "") or "arista" in conn_params.get("device_type", ""):
            net.enable()
        output = net.send_command(f"show interface {intf}")
        return output[:500]


def apply_rate_limit(conn_params, intf):
    return _send_remediation(conn_params, intf, "limit", limit_mbps=50)


def remove_rate_limit_router(conn_params, intf):
    return _send_remediation(conn_params, intf, "removelimit", limit_mbps=50)


@client.event
async def on_ready():
    log.info(f"✅ Discord Bot พร้อมใช้งาน: {client.user}")
    client.loop.create_task(process_anomaly_queue())


@client.event
async def on_message(message):
    if message.author == client.user:
        return

    if message.content.startswith("!history"):
        rows = get_anomaly_history(limit=10)
        if not rows:
            await message.channel.send("✅ ไม่มี anomaly history")
            return
        embed = discord.Embed(
            title="📋 Anomaly History (10 รายการล่าสุด)", color=discord.Color.orange(), timestamp=datetime.now()
        )
        for row in rows:
            status = "✅ Fixed" if row[5] else "🔴 Not Fixed"
            src = row[10] if len(row) > 10 and row[10] else "—"
            name_val = f"{row[1]}" if row[2] == "ALL" else f"{row[1]} - {row[2]}"
            embed.add_field(
                name=name_val,
                value=(
                    f"เวลา: {row[0].strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"Status: {status}\n"
                    f"Confidence: {row[4]:.0%}\n"
                    f"Detection: {src}"
                ),
                inline=True,
            )
        await message.channel.send(embed=embed)

    if message.content.startswith("!status"):
        rows = get_device_status()
        if not rows:
            await message.channel.send("❌ ไม่มีข้อมูล")
            return
        embed = discord.Embed(title="📡 Network Status", color=discord.Color.green(), timestamp=datetime.now())
        for row in rows:
            label = row[8]
            status_emoji = "✅" if label == "normal" else "🚨"
            name_val = f"{row[0]}" if row[1] == "ALL" else f"{row[0]} - {row[1]}"
            embed.add_field(
                name=status_emoji + " " + name_val,
                value=f"IP: {row[2]}\nStatus: {row[3]}/{row[4]}\nLoad: {row[5]}/{row[6]}",
                inline=True,
            )
        await message.channel.send(embed=embed)

    if message.content.startswith("!help"):
        embed = discord.Embed(title="📖 Commands", description="คำสั่งที่ใช้ได้", color=discord.Color.blue())
        embed.add_field(name="!status", value="ดู status ทุก interface ตอนนี้", inline=False)
        embed.add_field(name="!history", value="ดู anomaly 10 รายการล่าสุด", inline=False)
        embed.add_field(name="!analytics", value="สรุป anomaly, uptime, fix rate, traffic", inline=False)
        embed.add_field(name="!help", value="แสดงคำสั่งทั้งหมด", inline=False)
        await message.channel.send(embed=embed)

    if message.content.startswith("!analytics"):
        data = get_analytics()
        embed1 = discord.Embed(
            title="📊 Network Analytics — Overview", color=discord.Color.blurple(), timestamp=datetime.now()
        )
        s = data["summary"]
        embed1.add_field(name="📦 Total Records", value=f"{s[0]:,} logs", inline=True)
        embed1.add_field(name="🚨 Total Anomaly", value=f"{s[1]:,} ({s[3]}%)", inline=True)
        embed1.add_field(name="✅ Total Normal", value=f"{s[2]:,}", inline=True)
        embed1.add_field(name="🗓️ Anomaly Today", value=f"{data['today'][0]:,} cases", inline=True)
        fr = data["fix_rate"]
        embed1.add_field(name="🔧 Fix Rate", value=f"{fr[1]}/{fr[0]} ({fr[2]}%)", inline=True)
        await message.channel.send(embed=embed1)

        embed2 = discord.Embed(title="⏱️ Device Uptime", color=discord.Color.green())
        for row in data["uptime"]:
            uptime_pct = row[1]
            emoji = "🟢" if uptime_pct >= 99 else "🟡" if uptime_pct >= 95 else "🔴"
            embed2.add_field(
                name=f"{emoji} {row[0]}", value=f"Uptime: **{uptime_pct}%**\nRecords: {row[2]:,}", inline=True
            )
        await message.channel.send(embed=embed2)

        embed3 = discord.Embed(title="🏆 Top Problem Devices & Interfaces", color=discord.Color.red())
        top_dev_text = (
            "\n".join([f"{i+1}. **{row[0]}** — {row[1]:,} anomalies" for i, row in enumerate(data["top_devices"])])
            or "ไม่มีข้อมูล"
        )
        top_intf_text = (
            "\n".join(
                [f"{i+1}. **{row[0]}** {row[1]} — {row[2]:,} anomalies" for i, row in enumerate(data["top_interfaces"])]
            )
            or "ไม่มีข้อมูล"
        )
        embed3.add_field(name="📡 Top Devices", value=top_dev_text, inline=True)
        embed3.add_field(name="🔌 Top Interfaces", value=top_intf_text, inline=True)
        await message.channel.send(embed=embed3)

        embed4 = discord.Embed(title="📈 Traffic Trend (6 ชั่วโมงล่าสุด)", color=discord.Color.orange())
        if data["traffic_trend"]:
            trend_text = ""
            for row in data["traffic_trend"]:
                load_pct = round(row[1] / 255 * 100, 1)
                max_pct = round(row[2] / 255 * 100, 1)
                bar = "🔴" if load_pct > 50 else "🟡" if load_pct > 20 else "🟢"
                trend_text += f"{bar} **{row[0]}** — avg {load_pct}% | max {max_pct}%\n"
            embed4.add_field(name="Load per Hour", value=trend_text, inline=False)
        else:
            embed4.add_field(name="Load per Hour", value="ไม่มีข้อมูล", inline=False)
        await message.channel.send(embed=embed4)

        embed5 = discord.Embed(title="🔍 Anomaly by Type", color=discord.Color.dark_red())
        type_text = ""
        for row in data["anomaly_by_type"]:
            if row[0] == "admin_down":
                emoji = "🔴 Admin Down"
            elif row[0] == "up" and row[1] == "down":
                emoji = "🟠 Protocol Down"
            elif row[0] == "down":
                emoji = "⚫ Physical Down"
            else:
                emoji = "🟡 High Traffic"
            type_text += f"{emoji} — **{row[2]:,}** cases\n"
        embed5.add_field(name="Breakdown", value=type_text or "ไม่มีข้อมูล", inline=False)
        await message.channel.send(embed=embed5)


async def process_anomaly_queue():
    while not shutdown_event.is_set():
        try:
            anomaly = await asyncio.wait_for(anomaly_queue.get(), timeout=1.0)
            await send_anomaly_alert(anomaly)
        except asyncio.TimeoutError:
            continue
        except Exception as e:
            log.error("Bot error in process_anomaly_queue: %s", e)


def run_bot():
    if not DISCORD_TOKEN:
        log.warning("DISCORD_TOKEN ไม่ได้กำหนดใน .env — Discord Bot จะไม่ทำงาน")
        return
    client.run(DISCORD_TOKEN)
