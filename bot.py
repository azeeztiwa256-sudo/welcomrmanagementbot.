"""
Telegram Welcome & Group Management Bot — Complete Application
==============================================================
Run locally:      python bot.py
Deploy Railway:   push to GitHub, connect repo, set env vars, service type = Worker.

Sections:
  1.  Settings
  2.  Database models
  3.  Engine, seeding, session helper
  4.  Repositories (groups, members, warnings, moderation, verification, etc.)
  5.  Keyboards
  6.  FSM states
  7.  Middlewares (DB, throttle, group context, admin guard)
  8.  Utilities (permissions check, time, templating, URL/keyword scan)
  9.  Verification service (math CAPTCHA)
  10. Anti-spam / anti-link / anti-raid services
  11. Warning/punishment service
  12. Member lifecycle handlers (join / leave)
  13. Moderation handlers (msg scan → actions)
  14. User-facing commands (/start, /help, /rules, /report)
  15. Admin commands (welcome, verify, antispam, warn, mute, kick, ban, purge, lock, settings, stats, ...)
  16. Verification callback handler
  17. Web dashboard (optional FastAPI)
  18. Bootstrap (polling)
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import secrets
import string
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from enum import Enum
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

from aiogram import BaseMiddleware, Bot, Dispatcher, F, Router
from aiogram.enums import ChatMemberStatus, ChatType, ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    CallbackQuery, ChatMemberUpdated, InlineKeyboardMarkup, Message,
    TelegramObject,
)
from aiogram.utils.keyboard import InlineKeyboardBuilder
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import (
    BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text,
    UniqueConstraint, delete, func, select,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# ═══════════════════════════════════════════════════════════════════════
# 1. SETTINGS
# ═══════════════════════════════════════════════════════════════════════
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
log = logging.getLogger("mgmtbot")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    bot_token: str
    owner_ids: str = ""

    database_url: str = "sqlite+aiosqlite:///./bot.db"

    default_welcome: str = "👋 Welcome {first_name} to {group_name}! Please verify to join."
    verify_timeout_seconds: int = 180
    default_warn_limit: int = 3
    mute_seconds: int = 600
    raid_join_threshold: int = 10
    raid_window_seconds: int = 60

    web_dashboard_enabled: bool = False
    web_dashboard_host: str = "0.0.0.0"
    web_dashboard_port: int = 8080
    web_dashboard_password: str = "change-me"

    log_level: str = "INFO"

    @property
    def owner_id_list(self) -> list[int]:
        return [int(x.strip()) for x in self.owner_ids.split(",") if x.strip().isdigit()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
logging.getLogger().setLevel(settings.log_level)


# ═══════════════════════════════════════════════════════════════════════
# 2. DATABASE MODELS
# ═══════════════════════════════════════════════════════════════════════
class Base(DeclarativeBase):
    pass


class Group(Base):
    __tablename__ = "groups"
    chat_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    title: Mapped[str] = mapped_column(String(255), default="")
    added_by: Mapped[int | None] = mapped_column(BigInteger)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    group_settings: Mapped["GroupSettings"] = relationship(
        back_populates="group", uselist=False, cascade="all, delete-orphan"
    )


class GroupSettings(Base):
    __tablename__ = "group_settings"
    chat_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("groups.chat_id"), primary_key=True)

    welcome_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    welcome_text: Mapped[str] = mapped_column(Text, default="")
    welcome_delete_after: Mapped[int] = mapped_column(Integer, default=0)
    goodbye_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    goodbye_text: Mapped[str] = mapped_column(Text, default="👋 Goodbye {first_name}.")

    verify_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    verify_timeout: Mapped[int] = mapped_column(Integer, default=180)
    verify_max_attempts: Mapped[int] = mapped_column(Integer, default=3)

    antispam_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    antispam_msg_per_window: Mapped[int] = mapped_column(Integer, default=6)
    antispam_window_sec: Mapped[int] = mapped_column(Integer, default=5)
    antilink_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    antilink_allow_admins: Mapped[bool] = mapped_column(Boolean, default=True)

    antiraid_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    lockdown: Mapped[bool] = mapped_column(Boolean, default=False)
    raid_threshold: Mapped[int] = mapped_column(Integer, default=10)
    raid_window_sec: Mapped[int] = mapped_column(Integer, default=60)

    warn_limit: Mapped[int] = mapped_column(Integer, default=3)
    mute_seconds: Mapped[int] = mapped_column(Integer, default=600)

    flood_lock: Mapped[bool] = mapped_column(Boolean, default=False)
    media_lock: Mapped[bool] = mapped_column(Boolean, default=False)
    stickers_lock: Mapped[bool] = mapped_column(Boolean, default=False)
    gif_lock: Mapped[bool] = mapped_column(Boolean, default=False)

    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    group: Mapped["Group"] = relationship(back_populates="group_settings")


class Member(Base):
    __tablename__ = "members"
    id: Mapped[int] = mapped_column(primary_key=True)
    chat_id: Mapped[int] = mapped_column(BigInteger, index=True)
    user_id: Mapped[int] = mapped_column(BigInteger, index=True)
    first_name: Mapped[str | None] = mapped_column(String(128))
    username: Mapped[str | None] = mapped_column(String(64))
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    trusted: Mapped[bool] = mapped_column(Boolean, default=False)
    warn_count: Mapped[int] = mapped_column(Integer, default=0)
    joined_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    left_at: Mapped[datetime | None] = mapped_column(DateTime)

    __table_args__ = (UniqueConstraint("chat_id", "user_id", name="uq_member"),)


class Warning(Base):
    __tablename__ = "warnings"
    id: Mapped[int] = mapped_column(primary_key=True)
    chat_id: Mapped[int] = mapped_column(BigInteger, index=True)
    user_id: Mapped[int] = mapped_column(BigInteger, index=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    issued_by: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)
    active: Mapped[bool] = mapped_column(Boolean, default=True)

    __table_args__ = (Index("idx_warn_active", "chat_id", "user_id", "active"),)


class ModerationAction(Base):
    __tablename__ = "moderation_actions"
    id: Mapped[int] = mapped_column(primary_key=True)
    chat_id: Mapped[int] = mapped_column(BigInteger, index=True)
    user_id: Mapped[int] = mapped_column(BigInteger, index=True)
    action: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(Text, default="")
    by_bot: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class BannedUser(Base):
    __tablename__ = "banned_users"
    chat_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    user_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    until: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class MutedUser(Base):
    __tablename__ = "muted_users"
    chat_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    user_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    until: Mapped[datetime] = mapped_column(DateTime)
    reason: Mapped[str] = mapped_column(Text, default="")


class VerificationRecord(Base):
    __tablename__ = "verification_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    chat_id: Mapped[int] = mapped_column(BigInteger, index=True)
    user_id: Mapped[int] = mapped_column(BigInteger, index=True)
    challenge: Mapped[str] = mapped_column(String(128))
    answer: Mapped[str] = mapped_column(String(32))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)

    __table_args__ = (Index("idx_verify_active", "chat_id", "user_id", "status"),)


class BlockedKeyword(Base):
    __tablename__ = "blocked_keywords"
    id: Mapped[int] = mapped_column(primary_key=True)
    chat_id: Mapped[int] = mapped_column(BigInteger, index=True)
    keyword: Mapped[str] = mapped_column(String(128))


class AllowedLink(Base):
    __tablename__ = "allowed_links"
    id: Mapped[int] = mapped_column(primary_key=True)
    chat_id: Mapped[int] = mapped_column(BigInteger, index=True)
    domain: Mapped[str] = mapped_column(String(255))


class Rule(Base):
    __tablename__ = "rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    chat_id: Mapped[int] = mapped_column(BigInteger, index=True)
    order: Mapped[int] = mapped_column(Integer, default=0)
    text: Mapped[str] = mapped_column(Text)


class ActivityLog(Base):
    __tablename__ = "activity_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    chat_id: Mapped[int] = mapped_column(BigInteger, index=True)
    event_type: Mapped[str] = mapped_column(String(64))
    payload: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class JoinEvent(Base):
    __tablename__ = "join_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    chat_id: Mapped[int] = mapped_column(BigInteger, index=True)
    user_id: Mapped[int] = mapped_column(BigInteger)
    ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (Index("idx_join_window", "chat_id", "ts"),)


# ═══════════════════════════════════════════════════════════════════════
# 3. ENGINE / SEED / SESSION
# ═══════════════════════════════════════════════════════════════════════
engine = create_async_engine(settings.database_url, echo=False, future=True)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    log.info("DB initialized.")


@asynccontextmanager
async def session_scope():
    async with SessionLocal() as s:
        try:
            yield s
            await s.commit()
        except Exception:
            await s.rollback()
            raise


# ═══════════════════════════════════════════════════════════════════════
# 4. REPOSITORIES
# ═══════════════════════════════════════════════════════════════════════
async def get_or_create_group(s: AsyncSession, chat_id: int, title: str = "",
                              added_by: int | None = None) -> Group:
    g = await s.get(Group, chat_id)
    if g is None:
        g = Group(chat_id=chat_id, title=title or "", added_by=added_by)
        s.add(g)
        s.add(GroupSettings(
            chat_id=chat_id,
            welcome_text=settings.default_welcome,
            verify_timeout=settings.verify_timeout_seconds,
            warn_limit=settings.default_warn_limit,
            mute_seconds=settings.mute_seconds,
            raid_threshold=settings.raid_join_threshold,
            raid_window_sec=settings.raid_window_seconds,
        ))
        await s.flush()
    else:
        if title and g.title != title:
            g.title = title
    return g


async def get_settings_row(s: AsyncSession, chat_id: int) -> GroupSettings | None:
    return await s.get(GroupSettings, chat_id)


async def upsert_member(s: AsyncSession, chat_id: int, user_id: int,
                        first_name: str | None = None,
                        username: str | None = None) -> Member:
    q = select(Member).where(Member.chat_id == chat_id, Member.user_id == user_id)
    m = (await s.execute(q)).scalars().first()
    if m is None:
        m = Member(chat_id=chat_id, user_id=user_id,
                   first_name=first_name, username=username)
        s.add(m)
        await s.flush()
    else:
        if first_name:
            m.first_name = first_name
        if username is not None:
            m.username = username
        if m.left_at:
            m.left_at = None
    return m


async def mark_member_left(s: AsyncSession, chat_id: int, user_id: int) -> None:
    q = select(Member).where(Member.chat_id == chat_id, Member.user_id == user_id)
    m = (await s.execute(q)).scalars().first()
    if m:
        m.left_at = datetime.utcnow()
        m.verified = False


async def add_warning(s: AsyncSession, chat_id: int, user_id: int, reason: str,
                      issued_by: int, ttl_hours: int = 72) -> Warning:
    w = Warning(chat_id=chat_id, user_id=user_id, reason=reason,
                issued_by=issued_by,
                expires_at=datetime.utcnow() + timedelta(hours=ttl_hours))
    s.add(w)
    await s.flush()
    await update_member_warn_count(s, chat_id, user_id)
    return w


async def update_member_warn_count(s: AsyncSession, chat_id: int, user_id: int) -> int:
    n = (await s.execute(
        select(func.count()).select_from(Warning).where(
            Warning.chat_id == chat_id,
            Warning.user_id == user_id,
            Warning.active.is_(True),
        )
    )).scalar() or 0
    q = select(Member).where(Member.chat_id == chat_id, Member.user_id == user_id)
    m = (await s.execute(q)).scalars().first()
    if m:
        m.warn_count = n
    return n


async def list_active_warnings(s: AsyncSession, chat_id: int, user_id: int) -> list[Warning]:
    return list((await s.execute(
        select(Warning).where(
            Warning.chat_id == chat_id,
            Warning.user_id == user_id,
            Warning.active.is_(True),
        ).order_by(Warning.created_at.desc())
    )).scalars())


async def log_action(s: AsyncSession, chat_id: int, user_id: int, action: str,
                     reason: str = "", by_bot: bool = True) -> None:
    s.add(ModerationAction(chat_id=chat_id, user_id=user_id,
                           action=action, reason=reason, by_bot=by_bot))


async def log_activity(s: AsyncSession, chat_id: int, event_type: str,
                       payload: dict | None = None) -> None:
    s.add(ActivityLog(chat_id=chat_id, event_type=event_type,
                      payload=json.dumps(payload or {})))


async def record_join(s: AsyncSession, chat_id: int, user_id: int) -> int:
    s.add(JoinEvent(chat_id=chat_id, user_id=user_id))
    await s.flush()
    since = datetime.utcnow() - timedelta(seconds=settings.raid_window_seconds)
    return (await s.execute(
        select(func.count()).select_from(JoinEvent).where(
            JoinEvent.chat_id == chat_id, JoinEvent.ts >= since
        )
    )).scalar() or 0


async def create_verification(s: AsyncSession, chat_id: int, user_id: int,
                              challenge: str, answer: str, timeout: int) -> VerificationRecord:
    vr = VerificationRecord(
        chat_id=chat_id, user_id=user_id, challenge=challenge, answer=answer,
        expires_at=datetime.utcnow() + timedelta(seconds=timeout),
    )
    s.add(vr)
    await s.flush()
    return vr


async def get_pending_verification(s: AsyncSession, chat_id: int,
                                   user_id: int) -> VerificationRecord | None:
    q = (select(VerificationRecord)
         .where(VerificationRecord.chat_id == chat_id,
                VerificationRecord.user_id == user_id,
                VerificationRecord.status == "pending")
         .order_by(VerificationRecord.id.desc()))
    return (await s.execute(q)).scalars().first()


async def mark_verified(s: AsyncSession, chat_id: int, user_id: int) -> None:
    q = select(Member).where(Member.chat_id == chat_id, Member.user_id == user_id)
    m = (await s.execute(q)).scalars().first()
    if m:
        m.verified = True
    vr = await get_pending_verification(s, chat_id, user_id)
    if vr:
        vr.status = "passed"


async def list_blocked_keywords(s: AsyncSession, chat_id: int) -> list[str]:
    return list((await s.execute(
        select(BlockedKeyword.keyword).where(BlockedKeyword.chat_id == chat_id)
    )).scalars())


async def list_allowed_links(s: AsyncSession, chat_id: int) -> list[str]:
    return list((await s.execute(
        select(AllowedLink.domain).where(AllowedLink.chat_id == chat_id)
    )).scalars())


async def get_rules(s: AsyncSession, chat_id: int) -> list[Rule]:
    return list((await s.execute(
        select(Rule).where(Rule.chat_id == chat_id).order_by(Rule.order, Rule.id)
    )).scalars())


async def group_stats(s: AsyncSession, chat_id: int) -> dict[str, int]:
    total = (await s.execute(
        select(func.count()).select_from(Member).where(Member.chat_id == chat_id, Member.left_at.is_(None))
    )).scalar() or 0
    verified = (await s.execute(
        select(func.count()).select_from(Member).where(
            Member.chat_id == chat_id, Member.verified.is_(True), Member.left_at.is_(None)
        )
    )).scalar() or 0
    warns = (await s.execute(
        select(func.count()).select_from(Warning).where(
            Warning.chat_id == chat_id, Warning.active.is_(True)
        )
    )).scalar() or 0
    mutes = (await s.execute(
        select(func.count()).select_from(MutedUser).where(MutedUser.chat_id == chat_id)
    )).scalar() or 0
    bans = (await s.execute(
        select(func.count()).select_from(BannedUser).where(BannedUser.chat_id == chat_id)
    )).scalar() or 0
    actions = (await s.execute(
        select(func.count()).select_from(ModerationAction).where(ModerationAction.chat_id == chat_id)
    )).scalar() or 0
    return {
        "members": total, "verified": verified, "unverified": total - verified,
        "warnings": warns, "muted": mutes, "banned": bans, "actions": actions,
    }


# ═══════════════════════════════════════════════════════════════════════
# 5. KEYBOARDS
# ═══════════════════════════════════════════════════════════════════════
def main_menu() -> InlineKeyboardMarkup:
    kb = InlineKeyboardBuilder()
    kb.button(text="❓ Help", callback_data="menu:help")
    kb.button(text="📜 Rules", callback_data="menu:rules")
    kb.button(text="📊 Stats", callback_data="menu:stats")
    kb.adjust(3)
    return kb.as_markup()


def verify_captcha_kb(record_id: int, correct: int, wrong_a: int, wrong_b: int) -> InlineKeyboardMarkup:
    options = [correct, wrong_a, wrong_b]
    random.shuffle(options)
    kb = InlineKeyboardBuilder()
    for val in options:
        kb.button(text=str(val), callback_data=f"vrf:{record_id}:{val}")
    kb.adjust(3)
    return kb.as_markup()


def back_home() -> InlineKeyboardMarkup:
    kb = InlineKeyboardBuilder()
    kb.button(text="🏠 Menu", callback_data="menu:home")
    return kb.as_markup()


# ═══════════════════════════════════════════════════════════════════════
# 6. FSM STATES
# ═══════════════════════════════════════════════════════════════════════
class AdminSetWelcome(StatesGroup):
    waiting = State()


class AdminSetGoodbye(StatesGroup):
    waiting = State()


class AdminAddRule(StatesGroup):
    waiting = State()


class AdminAddKeyword(StatesGroup):
    waiting = State()


class AdminAddAllowedLink(StatesGroup):
    waiting = State()


class AdminMute(StatesGroup):
    waiting_user = State()
    waiting_reason = State()


class AdminWarn(StatesGroup):
    waiting_user = State()
    waiting_reason = State()


class AdminBan(StatesGroup):
    waiting_user = State()
    waiting_reason = State()


class ReportFlow(StatesGroup):
    waiting = State()


# ═══════════════════════════════════════════════════════════════════════
# 7. MIDDLEWARES
# ═══════════════════════════════════════════════════════════════════════
class DBMiddleware(BaseMiddleware):
    async def __call__(self, handler, event: TelegramObject, data: dict[str, Any]):
        async with SessionLocal() as s:
            data["session"] = s
            try:
                r = await handler(event, data)
                await s.commit()
                return r
            except Exception:
                await s.rollback()
                raise


class ThrottleMiddleware(BaseMiddleware):
    _cd: dict[int, float] = {}

    async def __call__(self, handler, event: TelegramObject, data: dict[str, Any]):
        if not isinstance(event, Message) or event.from_user is None:
            return await handler(event, data)
        uid = event.from_user.id
        if uid in settings.owner_id_list:
            return await handler(event, data)
        now = time.monotonic()
        if now - self._cd.get(uid, 0) < 1.0:
            return None
        self._cd[uid] = now
        return await handler(event, data)


class GroupContextMiddleware(BaseMiddleware):
    """Loads/creates group + settings; blocks if group is inactive."""

    async def __call__(self, handler, event: TelegramObject, data: dict[str, Any]):
        chat = getattr(event, "chat", None)
        session: AsyncSession = data["session"]
        if chat and chat.type in (ChatType.GROUP, ChatType.SUPERGROUP):
            added_by = event.from_user.id if getattr(event, "from_user", None) else None
            await get_or_create_group(session, chat.id, chat.title or "", added_by)
            gs = await get_settings_row(session, chat.id)
            data["group_settings"] = gs
        return await handler(event, data)


# ═══════════════════════════════════════════════════════════════════════
# 8. UTILITIES
# ═══════════════════════════════════════════════════════════════════════
URL_RE = re.compile(r"(https?://\S+|t\.me/\S+|www\.\S+)", re.IGNORECASE)


def render_template(template: str, *, first_name: str = "", username: str = "",
                    group_name: str = "", user_id: int = 0, member_count: int = 0) -> str:
    try:
        return template.format(
            first_name=first_name or "there",
            username=f"@{username}" if username else "",
            group_name=group_name or "the group",
            user_id=user_id,
            member_count=member_count,
        )
    except Exception:
        return template


def extract_domains(text: str) -> list[str]:
    domains: list[str] = []
    for m in URL_RE.findall(text or ""):
        try:
            if "://" not in m:
                m2 = "http://" + m
            else:
                m2 = m
            host = urlparse(m2).netloc.lower()
            if host.startswith("www."):
                host = host[4:]
            if host:
                domains.append(host)
        except Exception:
            pass
    return domains


def contains_blocked_keyword(text: str, keywords: list[str]) -> str | None:
    if not text:
        return None
    low = text.lower()
    for kw in keywords:
        if kw and kw.lower() in low:
            return kw
    return None


async def is_group_admin(bot: Bot, chat_id: int, user_id: int) -> bool:
    if user_id in settings.owner_id_list:
        return True
    try:
        m = await bot.get_chat_member(chat_id, user_id)
        return m.status in (ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.CREATOR)
    except Exception:
        return False


async def bot_can_restrict(bot: Bot, chat_id: int) -> bool:
    try:
        me = await bot.get_chat_member(chat_id, bot.id)
        return bool(me.can_restrict_members) or me.status == ChatMemberStatus.CREATOR
    except Exception:
        return False


async def bot_can_delete(bot: Bot, chat_id: int) -> bool:
    try:
        me = await bot.get_chat_member(chat_id, bot.id)
        return bool(me.can_delete_messages) or me.status == ChatMemberStatus.CREATOR
    except Exception:
        return False


def _gen_math_challenge() -> tuple[str, str]:
    a = random.randint(2, 9)
    b = random.randint(2, 9)
    op = random.choice(["+", "-", "×"])
    if op == "+":
        ans = a + b
    elif op == "-":
        if a < b:
            a, b = b, a
        ans = a - b
    else:
        ans = a * b
    return f"{a} {op} {b} = ?", str(ans)


# ═══════════════════════════════════════════════════════════════════════
# 9. VERIFICATION SERVICE
# ═══════════════════════════════════════════════════════════════════════
async def start_verification(bot: Bot, s: AsyncSession, chat_id: int, user_id: int,
                             first_name: str, gs: GroupSettings) -> None:
    if not gs.verify_enabled:
        return
    challenge, answer = _gen_math_challenge()
    vr = await create_verification(s, chat_id, user_id, challenge, answer, gs.verify_timeout)

    # Restrict user until verified
    if await bot_can_restrict(bot, chat_id):
        try:
            from aiogram.types import ChatPermissions
            await bot.restrict_chat_member(
                chat_id, user_id, permissions=ChatPermissions(can_send_messages=False)
            )
        except Exception as e:
            log.warning("restrict failed: %s", e)

    wrongs = set()
    while len(wrongs) < 2:
        w = random.randint(max(1, int(answer) - 5), int(answer) + 5)
        if str(w) != answer:
            wrongs.add(w)
    wrong_a, wrong_b = wrongs.pop(), wrongs.pop()

    msg = await bot.send_message(
        chat_id,
        f"🔐 Hi {first_name}, please solve: *{challenge}*\n"
        f"You have {gs.verify_timeout}s to verify.",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=verify_captcha_kb(vr.id, int(answer), wrong_a, wrong_b),
    )
    asyncio.create_task(_verify_timeout(bot, chat_id, user_id, vr.id, msg.message_id, gs.verify_timeout))


async def _verify_timeout(bot: Bot, chat_id: int, user_id: int, vr_id: int,
                          msg_id: int, timeout: int) -> None:
    await asyncio.sleep(timeout)
    async with SessionLocal() as s:
        vr = await s.get(VerificationRecord, vr_id)
        if vr and vr.status == "pending":
            vr.status = "expired"
            await s.commit()
            try:
                await bot.delete_message(chat_id, msg_id)
            except Exception:
                pass
            try:
                await bot.ban_chat_member(chat_id, user_id)
                await bot.unban_chat_member(chat_id, user_id)
            except Exception as e:
                log.warning("kick unverified failed: %s", e)


# ═══════════════════════════════════════════════════════════════════════
# 10. ANTI-SPAM / ANTI-LINK / ANTI-RAID
# ═══════════════════════════════════════════════════════════════════════
_recent_msgs: dict[tuple[int, int], list[float]] = {}


def spam_check(chat_id: int, user_id: int, gs: GroupSettings) -> bool:
    if not gs.antispam_enabled:
        return False
    now = time.monotonic()
    key = (chat_id, user_id)
    arr = _recent_msgs.setdefault(key, [])
    arr.append(now)
    cutoff = now - gs.antispam_window_sec
    while arr and arr[0] < cutoff:
        arr.pop(0)
    return len(arr) >= gs.antispam_msg_per_window


async def check_link_violation(s: AsyncSession, msg: Message, gs: GroupSettings,
                               bot: Bot) -> bool:
    if not gs.antilink_enabled:
        return False
    domains = extract_domains(msg.text or msg.caption or "")
    if not domains:
        return False
    if gs.antilink_allow_admins and msg.from_user:
        if await is_group_admin(bot, msg.chat.id, msg.from_user.id):
            return False
    allowed = await list_allowed_links(s, msg.chat.id)
    for d in domains:
        if not any(d == a or d.endswith("." + a) for a in allowed):
            return True
    return False


async def anti_raid_check(s: AsyncSession, chat_id: int, gs: GroupSettings) -> bool:
    if not gs.antiraid_enabled:
        return False
    since = datetime.utcnow() - timedelta(seconds=gs.raid_window_sec)
    cnt = (await s.execute(
        select(func.count()).select_from(JoinEvent).where(
            JoinEvent.chat_id == chat_id, JoinEvent.ts >= since
        )
    )).scalar() or 0
    return cnt >= gs.raid_threshold


# ═══════════════════════════════════════════════════════════════════════
# 11. WARNING / PUNISHMENT
# ═══════════════════════════════════════════════════════════════════════
async def apply_punishment(bot: Bot, s: AsyncSession, chat_id: int, user_id: int,
                           gs: GroupSettings, reason: str) -> str:
    warns = await update_member_warn_count(s, chat_id, user_id)
    if warns >= gs.warn_limit + 2:
        action = "ban"
        try:
            await bot.ban_chat_member(chat_id, user_id)
        except Exception:
            pass
        s.add(BannedUser(chat_id=chat_id, user_id=user_id, reason=reason))
    elif warns >= gs.warn_limit:
        action = "mute"
        until = datetime.utcnow() + timedelta(seconds=gs.mute_seconds)
        try:
            from aiogram.types import ChatPermissions
            await bot.restrict_chat_member(
                chat_id, user_id,
                permissions=ChatPermissions(can_send_messages=False),
                until_date=until,
            )
        except Exception:
            pass
        s.add(MutedUser(chat_id=chat_id, user_id=user_id, until=until, reason=reason))
    else:
        action = "warn"
    await log_action(s, chat_id, user_id, action, reason)
    return action


# ═══════════════════════════════════════════════════════════════════════
# 12. MEMBER LIFECYCLE HANDLERS
# ═══════════════════════════════════════════════════════════════════════
lifecycle_router = Router(name="lifecycle")


@lifecycle_router.chat_member()
async def on_chat_member(update: ChatMemberUpdated, bot: Bot, session: AsyncSession,
                         group_settings: GroupSettings):
    chat_id = update.chat.id
    user = update.new_chat_member.user
    old_status = update.old_chat_member.status
    new_status = update.new_chat_member.status

    joined = (old_status in (ChatMemberStatus.LEFT, ChatMemberStatus.KICKED)
              and new_status in (ChatMemberStatus.MEMBER, ChatMemberStatus.ADMINISTRATOR,
                                 ChatMemberStatus.RESTRICTED))
    left = (old_status not in (ChatMemberStatus.LEFT, ChatMemberStatus.KICKED)
            and new_status in (ChatMemberStatus.LEFT, ChatMemberStatus.KICKED))

    if joined and not user.is_bot:
        await upsert_member(session, chat_id, user.id, user.first_name, user.username)
        await record_join(session, chat_id, user.id)
        await log_activity(session, chat_id, "member_joined", {"user_id": user.id})

        if await anti_raid_check(session, chat_id, group_settings):
            group_settings.lockdown = True
            await log_activity(session, chat_id, "lockdown_enabled")

        if group_settings.lockdown:
            try:
                await bot.ban_chat_member(chat_id, user.id)
            except Exception:
                pass
            return

        if group_settings.welcome_enabled and group_settings.welcome_text:
            try:
                await bot.send_message(
                    chat_id,
                    render_template(
                        group_settings.welcome_text,
                        first_name=user.first_name or "",
                        username=user.username or "",
                        group_name=update.chat.title or "",
                        user_id=user.id,
                        member_count=await bot.get_chat_member_count(chat_id),
                    ),
                    reply_markup=main_menu(),
                )
            except Exception as e:
                log.warning("welcome send: %s", e)

        await start_verification(bot, session, chat_id, user.id,
                                 user.first_name or "", group_settings)

    elif left and not user.is_bot:
        await mark_member_left(session, chat_id, user.id)
        await log_activity(session, chat_id, "member_left", {"user_id": user.id})
        if group_settings.goodbye_enabled and group_settings.goodbye_text:
            try:
                await bot.send_message(
                    chat_id,
                    render_template(
                        group_settings.goodbye_text,
                        first_name=user.first_name or "",
                        group_name=update.chat.title or "",
                    ),
                )
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════
# 13. MODERATION (message scan)
# ═══════════════════════════════════════════════════════════════════════
mod_router = Router(name="moderation")


@mod_router.message(F.chat.type.in_({ChatType.GROUP, ChatType.SUPERGROUP}))
async def scan_message(m: Message, bot: Bot, session: AsyncSession,
                       group_settings: GroupSettings):
    if m.from_user is None or m.from_user.is_bot:
        return
    if await is_group_admin(bot, m.chat.id, m.from_user.id):
        return

    gs = group_settings
    reason = None

    if gs.media_lock and (m.photo or m.video or m.document):
        reason = "Media not allowed"
    elif gs.stickers_lock and m.sticker:
        reason = "Stickers not allowed"
    elif gs.gif_lock and m.animation:
        reason = "GIFs not allowed"
    elif spam_check(m.chat.id, m.from_user.id, gs):
        reason = "Spam (flood)"
    elif await check_link_violation(session, m, gs, bot):
        reason = "Link not allowed"
    else:
        kws = await list_blocked_keywords(session, m.chat.id)
        hit = contains_blocked_keyword(m.text or m.caption or "", kws)
        if hit:
            reason = f"Blocked keyword: {hit}"

    if not reason:
        return

    try:
        await m.delete()
    except Exception:
        pass

    await add_warning(session, m.chat.id, m.from_user.id, reason, bot.id)
    action = await apply_punishment(bot, session, m.chat.id, m.from_user.id, gs, reason)

    try:
        await bot.send_message(
            m.chat.id,
            f"⚠️ {m.from_user.mention} — {reason} ({action}).",
        )
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════
# 14. USER-FACING COMMANDS
# ═══════════════════════════════════════════════════════════════════════
user_router = Router(name="user")


@user_router.message(CommandStart())
async def cmd_start(m: Message):
    text = (
        "👋 *Welcome to the Group Management Bot!*\n\n"
        "I help admins welcome members, verify humans, and block spam.\n\n"
        "Admins: add me as *administrator* with delete/restrict permissions."
    )
    await m.answer(text, parse_mode=ParseMode.MARKDOWN, reply_markup=main_menu())


@user_router.message(Command("help"))
async def cmd_help(m: Message):
    text = (
        "*User commands*\n"
        "/start — welcome\n"
        "/help — this message\n"
        "/rules — show group rules\n"
        "/report — report a user\n\n"
        "*Admin commands*\n"
        "/setwelcome <text> — set welcome text\n"
        "/setgoodbye <text> — set goodbye text\n"
        "/welcome on|off\n"
        "/verify on|off\n"
        "/antispam on|off\n"
        "/antilink on|off\n"
        "/antiraid on|off\n"
        "/lockdown on|off\n"
        "/addrule <text> | /delrule <id> | /rules\n"
        "/addkeyword <word> | /delkeyword <word>\n"
        "/allowlink <domain> | /unallowlink <domain>\n"
        "/warn (reply) [reason] | /warnings (reply)\n"
        "/mute <seconds> (reply)\n"
        "/kick (reply)\n"
        "/ban (reply) [reason]\n"
        "/unban <user_id>\n"
        "/purge <count>\n"
        "/lock media|stickers|gifs on|off\n"
        "/settings — show config\n"
        "/stats — group stats\n"
    )
    await m.answer(text, parse_mode=ParseMode.MARKDOWN)


@user_router.message(Command("rules"))
async def cmd_rules(m: Message, session: AsyncSession):
    rows = await get_rules(session, m.chat.id)
    if not rows:
        await m.answer("No rules set yet. Admins: /addrule <text>")
        return
    text = "📜 *Group Rules*\n\n" + "\n".join(f"{r.order or i+1}. {r.text}" for i, r in enumerate(rows))
    await m.answer(text, parse_mode=ParseMode.MARKDOWN)


@user_router.message(Command("report"))
async def cmd_report(m: Message, state: FSMContext):
    await state.set_state(ReportFlow.waiting)
    await m.answer("Please describe the issue (a moderator will be notified).")


@user_router.message(ReportFlow.waiting)
async def report_received(m: Message, state: FSMContext, bot: Bot):
    await state.clear()
    chat_id = m.chat.id
    try:
        admins = await bot.get_chat_administrators(chat_id)
    except Exception:
        admins = []
    for a in admins:
        if a.user.is_bot:
            continue
        try:
            await bot.send_message(
                a.user.id,
                f"🚨 Report from {m.from_user.full_name} in {m.chat.title}:\n{m.text}",
            )
        except Exception:
            pass
    await m.answer("✅ Report sent to admins.")


@user_router.callback_query(F.data == "menu:home")
async def cb_home(cq: CallbackQuery):
    await cq.message.edit_text("📋 Menu", reply_markup=main_menu())
    await cq.answer()


@user_router.callback_query(F.data == "menu:help")
async def cb_help(cq: CallbackQuery):
    await cmd_help(cq.message)
    await cq.answer()


@user_router.callback_query(F.data == "menu:rules")
async def cb_rules(cq: CallbackQuery, session: AsyncSession):
    await cmd_rules(cq.message, session)
    await cq.answer()


@user_router.callback_query(F.data == "menu:stats")
async def cb_stats(cq: CallbackQuery, session: AsyncSession):
    st = await group_stats(session, cq.message.chat.id)
    await cq.message.answer(
        f"📊 *Group stats*\nMembers: {st['members']}\nVerified: {st['verified']}\n"
        f"Warnings: {st['warnings']}\nMuted: {st['muted']}\nBanned: {st['banned']}\n"
        f"Actions: {st['actions']}",
        parse_mode=ParseMode.MARKDOWN,
    )
    await cq.answer()


# ═══════════════════════════════════════════════════════════════════════
# 15. ADMIN COMMANDS
# ═══════════════════════════════════════════════════════════════════════
admin_router = Router(name="admin")


async def _guard_admin(m: Message, bot: Bot) -> bool:
    if m.chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
        await m.reply("This command only works in groups.")
        return False
    ok = await is_group_admin(bot, m.chat.id, m.from_user.id)
    if not ok:
        await m.reply("⛔ Admins only.")
    return ok


@admin_router.message(Command("setwelcome"))
async def cmd_setwelcome(m: Message, bot: Bot, session: AsyncSession):
    if not await _guard_admin(m, bot):
        return
    text = (m.text or "").partition(" ")[2].strip()
    if not text:
        await m.reply("Usage: /setwelcome <text with {first_name} {group_name}>")
        return
    gs = await get_settings_row(session, m.chat.id)
    gs.welcome_text = text
    await m.reply("✅ Welcome text updated.")


@admin_router.message(Command("setgoodbye"))
async def cmd_setgoodbye(m: Message, bot: Bot, session: AsyncSession):
    if not await _guard_admin(m, bot):
        return
    text = (m.text or "").partition(" ")[2].strip()
    if not text:
        await m.reply("Usage: /setgoodbye <text>")
        return
    gs = await get_settings_row(session, m.chat.id)
    gs.goodbye_text = text
    await m.reply("✅ Goodbye text updated.")


def _onoff(arg: str) -> bool | None:
    a = (arg or "").strip().lower()
    if a in ("on", "1", "true", "yes"):
        return True
    if a in ("off", "0", "false", "no"):
        return False
    return None


@admin_router.message(Command("welcome", "verify", "antispam", "antilink",
                              "antiraid", "lockdown", "goodbye"))
async def cmd_toggle(m: Message, bot: Bot, session: AsyncSession, command: Any = None):
    if not await _guard_admin(m, bot):
        return
    cmd = (m.text or "").split()[0].lstrip("/").lower()
    arg = (m.text or "").partition(" ")[2]
    val = _onoff(arg)
    if val is None:
        await m.reply(f"Usage: /{cmd} on|off")
        return
    gs = await get_settings_row(session, m.chat.id)
    mapping = {
        "welcome": "welcome_enabled",
        "goodbye": "goodbye_enabled",
        "verify": "verify_enabled",
        "antispam": "antispam_enabled",
        "antilink": "antilink_enabled",
        "antiraid": "antiraid_enabled",
        "lockdown": "lockdown",
    }
    setattr(gs, mapping[cmd], val)
    await m.reply(f"✅ {cmd} = {'on' if val else 'off'}")


@admin_router.message(Command("addrule"))
async def cmd_addrule(m: Message, bot: Bot, session: AsyncSession):
    if not await _guard_admin(m, bot):
        return
    text = (m.text or "").partition(" ")[2].strip()
    if not text:
        await m.reply("Usage: /addrule <text>")
        return
    existing = await get_rules(session, m.chat.id)
    session.add(Rule(chat_id=m.chat.id, order=len(existing) + 1, text=text))
    await m.reply("✅ Rule added.")


@admin_router.message(Command("delrule"))
async def cmd_delrule(m: Message, bot: Bot, session: AsyncSession):
    if not await _guard_admin(m, bot):
        return
    parts = (m.text or "").split()
    if len(parts) < 2 or not parts[1].isdigit():
        await m.reply("Usage: /delrule <id>")
        return
    r = await session.get(Rule, int(parts[1]))
    if r and r.chat_id == m.chat.id:
        await session.delete(r)
        await m.reply("🗑 Rule deleted.")
    else:
        await m.reply("Rule not found.")


@admin_router.message(Command("addkeyword"))
async def cmd_addkeyword(m: Message, bot: Bot, session: AsyncSession):
    if not await _guard_admin(m, bot):
        return
    kw = (m.text or "").partition(" ")[2].strip()
    if not kw:
        await m.reply("Usage: /addkeyword <word>")
        return
    session.add(BlockedKeyword(chat_id=m.chat.id, keyword=kw.lower()))
    await m.reply(f"✅ Blocked '{kw}'.")


@admin_router.message(Command("delkeyword"))
async def cmd_delkeyword(m: Message, bot: Bot, session: AsyncSession):
    if not await _guard_admin(m, bot):
        return
    kw = (m.text or "").partition(" ")[2].strip().lower()
    if not kw:
        await m.reply("Usage: /delkeyword <word>")
        return
    await session.execute(
        delete(BlockedKeyword).where(
            BlockedKeyword.chat_id == m.chat.id, BlockedKeyword.keyword == kw
        )
    )
    await m.reply("🗑 Removed.")


@admin_router.message(Command("allowlink"))
async def cmd_allowlink(m: Message, bot: Bot, session: AsyncSession):
    if not await _guard_admin(m, bot):
        return
    d = (m.text or "").partition(" ")[2].strip().lower().lstrip("www.")
    if not d:
        await m.reply("Usage: /allowlink <domain>")
        return
    session.add(AllowedLink(chat_id=m.chat.id, domain=d))
    await m.reply(f"✅ Allowed {d}")


@admin_router.message(Command("unallowlink"))
async def cmd_unallowlink(m: Message, bot: Bot, session: AsyncSession):
    if not await _guard_admin(m, bot):
        return
    d = (m.text or "").partition(" ")[2].strip().lower().lstrip("www.")
    await session.execute(
        delete(AllowedLink).where(
            AllowedLink.chat_id == m.chat.id, AllowedLink.domain == d
        )
    )
    await m.reply("🗑 Removed.")


@admin_router.message(Command("warn"))
async def cmd_warn(m: Message, bot: Bot, session: AsyncSession):
    if not await _guard_admin(m, bot):
        return
    if not m.reply_to_message or not m.reply_to_message.from_user:
        await m.reply("Reply to the user to warn.")
        return
    target = m.reply_to_message.from_user
    reason = (m.text or "").partition(" ")[2].strip() or "No reason"
    gs = await get_settings_row(session, m.chat.id)
    await add_warning(session, m.chat.id, target.id, reason, m.from_user.id)
    action = await apply_punishment(bot, session, m.chat.id, target.id, gs, reason)
    await m.reply(f"⚠️ {target.full_name} warned ({action}). Reason: {reason}")


@admin_router.message(Command("warnings"))
async def cmd_warnings(m: Message, bot: Bot, session: AsyncSession):
    if not await _guard_admin(m, bot):
        return
    target = m.reply_to_message.from_user if (m.reply_to_message and m.reply_to_message.from_user) else None
    if not target:
        await m.reply("Reply to the user to view warnings.")
        return
    warns = await list_active_warnings(session, m.chat.id, target.id)
    if not warns:
        await m.reply("No active warnings.")
        return
    lines = [f"#{w.id} — {w.reason} ({w.created_at:%Y-%m-%d %H:%M})" for w in warns]
    await m.reply(f"⚠️ Warnings for {target.full_name}:\n" + "\n".join(lines))


@admin_router.message(Command("mute"))
async def cmd_mute(m: Message, bot: Bot, session: AsyncSession):
    if not await _guard_admin(m, bot):
        return
    if not m.reply_to_message or not m.reply_to_message.from_user:
        await m.reply("Reply to the user to mute.")
        return
    parts = (m.text or "").split()
    seconds = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 600
    target = m.reply_to_message.from_user
    until = datetime.utcnow() + timedelta(seconds=seconds)
    try:
        from aiogram.types import ChatPermissions
        await bot.restrict_chat_member(
            m.chat.id, target.id,
            permissions=ChatPermissions(can_send_messages=False),
            until_date=until,
        )
    except Exception as e:
        await m.reply(f"Failed: {e}")
        return
    session.add(MutedUser(chat_id=m.chat.id, user_id=target.id,
                          until=until, reason="manual"))
    await log_action(session, m.chat.id, target.id, "mute", "manual", by_bot=False)
    await m.reply(f"🔇 Muted for {seconds}s.")


@admin_router.message(Command("unmute"))
async def cmd_unmute(m: Message, bot: Bot, session: AsyncSession):
    if not await _guard_admin(m, bot):
        return
    if not m.reply_to_message or not m.reply_to_message.from_user:
        await m.reply("Reply to the user to unmute.")
        return
    target = m.reply_to_message.from_user
    try:
        from aiogram.types import ChatPermissions
        await bot.restrict_chat_member(
            m.chat.id, target.id,
            permissions=ChatPermissions(
                can_send_messages=True, can_send_media_messages=True,
                can_send_other_messages=True, can_add_web_page_previews=True,
            ),
        )
    except Exception as e:
        await m.reply(f"Failed: {e}")
        return
    await session.execute(
        delete(MutedUser).where(
            MutedUser.chat_id == m.chat.id, MutedUser.user_id == target.id
        )
    )
    await m.reply("🔊 Unmuted.")


@admin_router.message(Command("kick"))
async def cmd_kick(m: Message, bot: Bot, session: AsyncSession):
    if not await _guard_admin(m, bot):
        return
    if not m.reply_to_message or not m.reply_to_message.from_user:
        await m.reply("Reply to the user to kick.")
        return
    target = m.reply_to_message.from_user
    try:
        await bot.ban_chat_member(m.chat.id, target.id)
        await bot.unban_chat_member(m.chat.id, target.id)
        await log_action(session, m.chat.id, target.id, "kick", "manual", by_bot=False)
        await m.reply(f"👢 Kicked {target.full_name}.")
    except Exception as e:
        await m.reply(f"Failed: {e}")


@admin_router.message(Command("ban"))
async def cmd_ban(m: Message, bot: Bot, session: AsyncSession):
    if not await _guard_admin(m, bot):
        return
    if not m.reply_to_message or not m.reply_to_message.from_user:
        await m.reply("Reply to the user to ban.")
        return
    target = m.reply_to_message.from_user
    reason = (m.text or "").partition(" ")[2].strip() or "manual"
    try:
        await bot.ban_chat_member(m.chat.id, target.id)
        session.add(BannedUser(chat_id=m.chat.id, user_id=target.id, reason=reason))
        await log_action(session, m.chat.id, target.id, "ban", reason, by_bot=False)
        await m.reply(f"🚫 Banned {target.full_name}.")
    except Exception as e:
        await m.reply(f"Failed: {e}")


@admin_router.message(Command("unban"))
async def cmd_unban(m: Message, bot: Bot, session: AsyncSession):
    if not await _guard_admin(m, bot):
        return
    parts = (m.text or "").split()
    if len(parts) < 2 or not parts[1].lstrip("-").isdigit():
        await m.reply("Usage: /unban <user_id>")
        return
    uid = int(parts[1])
    try:
        await bot.unban_chat_member(m.chat.id, uid)
        await session.execute(
            delete(BannedUser).where(
                BannedUser.chat_id == m.chat.id, BannedUser.user_id == uid
            )
        )
        await m.reply("✅ Unbanned.")
    except Exception as e:
        await m.reply(f"Failed: {e}")


@admin_router.message(Command("purge"))
async def cmd_purge(m: Message, bot: Bot):
    if not await _guard_admin(m, bot):
        return
    parts = (m.text or "").split()
    if len(parts) < 2 or not parts[1].isdigit():
        await m.reply("Usage: /purge <count>")
        return
    n = int(parts[1])
    deleted = 0
    for i in range(1, n + 1):
        try:
            await bot.delete_message(m.chat.id, m.message_id - i)
            deleted += 1
        except Exception:
            pass
    await m.reply(f"🧹 Purged {deleted} messages.")


@admin_router.message(Command("lock"))
async def cmd_lock(m: Message, bot: Bot, session: AsyncSession):
    if not await _guard_admin(m, bot):
        return
    parts = (m.text or "").split()
    if len(parts) < 3:
        await m.reply("Usage: /lock media|stickers|gifs on|off")
        return
    target, val = parts[1].lower(), _onoff(parts[2])
    if val is None:
        await m.reply("on|off only.")
        return
    gs = await get_settings_row(session, m.chat.id)
    field = {"media": "media_lock", "stickers": "stickers_lock", "gifs": "gif_lock"}.get(target)
    if not field:
        await m.reply("Unknown target.")
        return
    setattr(gs, field, val)
    await m.reply(f"✅ {target} lock = {val}")


@admin_router.message(Command("settings"))
async def cmd_settings(m: Message, bot: Bot, session: AsyncSession):
    if not await _guard_admin(m, bot):
        return
    gs = await get_settings_row(session, m.chat.id)
    if not gs:
        await m.reply("No settings yet.")
        return
    await m.reply(
        f"*Settings for {m.chat.title}*\n"
        f"Welcome: {gs.welcome_enabled} — `{gs.welcome_text[:40]}…`\n"
        f"Goodbye: {gs.goodbye_enabled}\n"
        f"Verify: {gs.verify_enabled} (timeout {gs.verify_timeout}s)\n"
        f"Anti-spam: {gs.antispam_enabled}\n"
        f"Anti-link: {gs.antilink_enabled}\n"
        f"Anti-raid: {gs.antiraid_enabled} (lockdown={gs.lockdown})\n"
        f"Warn limit: {gs.warn_limit}\n"
        f"Mute secs: {gs.mute_seconds}",
        parse_mode=ParseMode.MARKDOWN,
    )


@admin_router.message(Command("stats"))
async def cmd_admin_stats(m: Message, bot: Bot, session: AsyncSession):
    if not await _guard_admin(m, bot):
        return
    st = await group_stats(session, m.chat.id)
    await m.reply(
        f"📊 *Stats*\nMembers: {st['members']}\nVerified: {st['verified']}\n"
        f"Warnings: {st['warnings']}\nMuted: {st['muted']}\nBanned: {st['banned']}\n"
        f"Actions: {st['actions']}",
        parse_mode=ParseMode.MARKDOWN,
    )


@admin_router.message(Command("admin"))
async def cmd_admin(m: Message, bot: Bot):
    if not await _guard_admin(m, bot):
        return
    await m.reply(
        "*Admin quick help*\n"
        "/setwelcome <text>\n/setgoodbye <text>\n"
        "/welcome on|off\n/verify on|off\n/antispam on|off\n/antilink on|off\n"
        "/antiraid on|off\n/lockdown on|off\n"
        "/addrule <text> | /delrule <id> | /rules\n"
        "/addkeyword <word> | /delkeyword <word>\n"
        "/allowlink <domain> | /unallowlink <domain>\n"
        "/warn /warnings /mute /unmute /kick /ban /unban /purge\n"
        "/lock media|stickers|gifs on|off\n"
        "/settings /stats",
        parse_mode=ParseMode.MARKDOWN,
    )


# ═══════════════════════════════════════════════════════════════════════
# 16. VERIFICATION CALLBACK
# ═══════════════════════════════════════════════════════════════════════
verify_router = Router(name="verify")


@verify_router.callback_query(F.data.startswith("vrf:"))
async def cb_verify(cq: CallbackQuery, bot: Bot, session: AsyncSession):
    _, rid, value = cq.data.split(":")
    vr = await session.get(VerificationRecord, int(rid))
    if not vr or vr.status != "pending":
        await cq.answer("This challenge is no longer active.", show_alert=True)
        return
    if vr.user_id != cq.from_user.id:
        await cq.answer("This isn't your challenge.", show_alert=True)
        return
    if datetime.utcnow() > vr.expires_at:
        await cq.answer("Expired.", show_alert=True)
        return
    if value == vr.answer:
        vr.status = "passed"
        await mark_verified(session, vr.chat_id, vr.user_id)
        try:
            from aiogram.types import ChatPermissions
            await bot.restrict_chat_member(
                vr.chat_id, vr.user_id,
                permissions=ChatPermissions(
                    can_send_messages=True, can_send_media_messages=True,
                    can_send_other_messages=True, can_add_web_page_previews=True,
                ),
            )
        except Exception:
            pass
        await cq.message.edit_text(f"✅ Verified! Welcome, {cq.from_user.first_name}.")
        await log_activity(session, vr.chat_id, "verified", {"user_id": vr.user_id})
    else:
        vr.attempts += 1
        if vr.attempts >= 3:
            vr.status = "failed"
            await cq.message.edit_text("❌ Too many wrong attempts.")
            try:
                await bot.ban_chat_member(vr.chat_id, vr.user_id)
                await bot.unban_chat_member(vr.chat_id, vr.user_id)
            except Exception:
                pass
        else:
            await cq.answer(f"❌ Wrong. Attempt {vr.attempts}/3.", show_alert=True)


# ═══════════════════════════════════════════════════════════════════════
# 17. WEB DASHBOARD (optional)
# ═══════════════════════════════════════════════════════════════════════
def build_web_app():
    if not settings.web_dashboard_enabled:
        return None
    from fastapi import Depends, FastAPI, Header, HTTPException

    app = FastAPI(title="Group Management Bot Dashboard")

    def check_auth(x_admin_password: str | None = Header(default=None)):
        if x_admin_password != settings.web_dashboard_password:
            raise HTTPException(401, "Unauthorized")

    @app.get("/health")
    async def health():
        return {"ok": True}

    @app.get("/api/groups", dependencies=[Depends(check_auth)])
    async def groups():
        async with SessionLocal() as s:
            rows = list((await s.execute(select(Group))).scalars())
        return [{"chat_id": g.chat_id, "title": g.title, "active": g.active} for g in rows]

    @app.get("/api/groups/{chat_id}/stats", dependencies=[Depends(check_auth)])
    async def group_stats_api(chat_id: int):
        async with SessionLocal() as s:
            return await group_stats(s, chat_id)

    @app.get("/api/groups/{chat_id}/tickets", dependencies=[Depends(check_auth)])
    async def groups_warns(chat_id: int):
        async with SessionLocal() as s:
            rows = list((await s.execute(
                select(Warning).where(Warning.chat_id == chat_id, Warning.active.is_(True))
            )).scalars())
        return [
            {"id": w.id, "user_id": w.user_id, "reason": w.reason,
             "created_at": w.created_at.isoformat()}
            for w in rows
        ]

    return app


# ═══════════════════════════════════════════════════════════════════════
# 18. BOOTSTRAP
# ═══════════════════════════════════════════════════════════════════════
async def run_web(app):
    import uvicorn
    cfg = uvicorn.Config(app, host=settings.web_dashboard_host,
                         port=settings.web_dashboard_port, log_level="info")
    await uvicorn.Server(cfg).serve()


async def main():
    await init_db()
    log.info("Starting bot…")
    bot = Bot(token=settings.bot_token)
    dp = Dispatcher(storage=MemoryStorage())

    dp.message.middleware(ThrottleMiddleware())
    dp.message.middleware(DBMiddleware())
    dp.message.middleware(GroupContextMiddleware())
    dp.chat_member.middleware(DBMiddleware())
    dp.chat_member.middleware(GroupContextMiddleware())
    dp.callback_query.middleware(DBMiddleware())
    dp.callback_query.middleware(GroupContextMiddleware())

    dp.include_router(verify_router)
    dp.include_router(admin_router)
    dp.include_router(lifecycle_router)
    dp.include_router(mod_router)
    dp.include_router(user_router)

    web_app = build_web_app()
    if web_app:
        asyncio.create_task(run_web(web_app))
        log.info("Web dashboard at %s:%s",
                 settings.web_dashboard_host, settings.web_dashboard_port)

    await dp.start_polling(bot, allowed_updates=["message", "callback_query", "chat_member", "my_chat_member"])


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        log.info("Stopped.")
