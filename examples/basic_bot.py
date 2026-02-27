import asyncio
import logging
import sys

# Add waton to path so we can run directly
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from waton import App
from waton.app import filters

logging.basicConfig(level=logging.INFO)

app = App(storage_path="test_bot.db")

@app.on_ready
async def ready(ctx):
    print("Bot is up and running! We are connected to WhatsApp.")
    
@app.message(filters.text & filters.private)
async def on_private_text(ctx):
    # Auto reply to ping
    if ctx.text.lower() == "ping":
        print(f"Received ping from {ctx.from_jid}, replying...")
        await ctx.reply("pong from waton!")
        await ctx.react("🚀")

@app.command("/help")
async def help_command(ctx):
    await ctx.reply("Available commands:\n/help - Show this message\nping - Play ping pong")

if __name__ == "__main__":
    print("Starting waton basic bot example...")
    app.run()
