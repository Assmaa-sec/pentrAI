"""Transactional token-credit reservation and exact settlement for native scans."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (AuditEvent, OrganizationCreditAccount, Scan,
                     ScanCreditReservation, utcnow)


PROFILE_CREDITS = {"quick": 20_000, "standard": 80_000, "deep": 200_000}


class CreditRejected(ValueError):
    pass


def grant_credits(session: Session, organization_id: str, amount: int, *,
                  actor_id: str, reason: str) -> None:
    """Internal provisioning hook; never exposed as a customer credit-mint API."""
    if type(amount) is not int or not 0 < amount <= 10_000_000 or not reason.strip():
        raise CreditRejected("invalid credit grant")
    account = session.scalar(select(OrganizationCreditAccount).where(
        OrganizationCreditAccount.organization_id == organization_id).with_for_update())
    if account is None:
        account = OrganizationCreditAccount(organization_id=organization_id,
                                            available=0, reserved=0, spent=0)
        session.add(account)
        session.flush()
    account.available += amount
    session.add(AuditEvent(organization_id=organization_id, actor_id=actor_id,
                           action="credits.granted", payload={"amount": amount, "reason": reason}))


def reserve_scan_credits(session: Session, scan: Scan) -> ScanCreditReservation:
    if scan.execution_backend == "local_static" or scan.profile not in PROFILE_CREDITS:
        raise CreditRejected("native scan and known profile required")
    existing = session.get(ScanCreditReservation, scan.id)
    if existing is not None:
        return existing
    account = session.scalar(select(OrganizationCreditAccount).where(
        OrganizationCreditAccount.organization_id == scan.organization_id).with_for_update())
    amount = PROFILE_CREDITS[scan.profile] * max(scan.prompt_credit_rate, scan.completion_credit_rate)
    if account is None or account.available < amount:
        raise CreditRejected("insufficient assessment credits")
    account.available -= amount
    account.reserved += amount
    reservation = ScanCreditReservation(scan_id=scan.id, organization_id=scan.organization_id,
                                        reserved_credits=amount, charged_credits=0)
    session.add(reservation)
    session.add(AuditEvent(organization_id=scan.organization_id, scan_id=scan.id,
                           actor_id="credit-ledger", action="credits.reserved",
                           payload={"amount": amount}))
    session.flush()
    return reservation


def _usage_total(usage: dict[str, int]) -> int:
    if not isinstance(usage, dict):
        raise CreditRejected("model usage is invalid")
    if "total_tokens" not in usage and not {"prompt_tokens", "completion_tokens"} <= set(usage):
        raise CreditRejected("provider token usage is required")
    prompt = usage.get("prompt_tokens", 0)
    completion = usage.get("completion_tokens", 0)
    total = usage.get("total_tokens", prompt + completion)
    if (any(type(value) is not int or value < 0 for value in (prompt, completion, total))
            or total <= 0 or total < prompt + completion or total > 10_000_000):
        raise CreditRejected("model usage is invalid")
    return total


def _usage_cost(scan: Scan, usage: dict[str, int]) -> int:
    total = _usage_total(usage)
    prompt = usage.get("prompt_tokens", 0)
    completion = usage.get("completion_tokens", 0)
    if prompt + completion == 0:
        return total * max(scan.prompt_credit_rate, scan.completion_credit_rate)
    if total != prompt + completion:
        # Providers can include uncategorized tokens; charge at the higher rate.
        return (prompt * scan.prompt_credit_rate + completion * scan.completion_credit_rate
                + (total - prompt - completion) * max(scan.prompt_credit_rate, scan.completion_credit_rate))
    return prompt * scan.prompt_credit_rate + completion * scan.completion_credit_rate


def record_model_usage(session: Session, scan_id: str, usage: dict[str, int]) -> int:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise CreditRejected("scan is missing")
    amount = _usage_cost(scan, usage)
    reservation = session.scalar(select(ScanCreditReservation).where(
        ScanCreditReservation.scan_id == scan_id).with_for_update())
    if reservation is None:
        return amount  # pre-ledger fixture or migrated legacy scan
    if reservation.settled_at is not None:
        raise CreditRejected("scan credit reservation is closed")
    if reservation.released_at is not None:
        account = session.scalar(select(OrganizationCreditAccount).where(
            OrganizationCreditAccount.organization_id == reservation.organization_id).with_for_update())
        if account is None:
            raise CreditRejected("credit account is missing")
        account.available -= amount
        account.spent += amount
        reservation.charged_credits += amount
    reservation.metered_credits += amount
    session.add(AuditEvent(organization_id=reservation.organization_id,
                           scan_id=scan_id, actor_id="credit-ledger",
                           action="credits.model_usage",
                           payload={"usage": usage, "charged_credits": amount,
                                    "total_charged_credits": reservation.metered_credits,
                                    "model_id": scan.model_id}))
    session.flush()
    return reservation.metered_credits


def require_model_budget(session: Session, scan_id: str) -> None:
    reservation = session.get(ScanCreditReservation, scan_id)
    if reservation is not None and (
        reservation.settled_at is not None or reservation.released_at is not None
        or reservation.metered_credits >= reservation.reserved_credits
    ):
        raise CreditRejected("model work budget exhausted")


def settle_scan_credits(session: Session, scan: Scan, usage: dict[str, int]) -> int:
    total = _usage_cost(scan, usage)
    reservation = session.scalar(select(ScanCreditReservation).where(
        ScanCreditReservation.scan_id == scan.id,
        ScanCreditReservation.organization_id == scan.organization_id).with_for_update())
    if reservation is None:
        # Legacy pre-ledger scans remain readable during local migration.
        return 0
    if reservation.settled_at is not None:
        if reservation.charged_credits != total:
            raise CreditRejected("model usage changed after settlement")
        return total
    if reservation.released_at is not None:
        raise CreditRejected("scan credit reservation was released")
    if total != reservation.metered_credits:
        raise CreditRejected("runner usage differs from provider meter")
    account = session.scalar(select(OrganizationCreditAccount).where(
        OrganizationCreditAccount.organization_id == scan.organization_id).with_for_update())
    if account is None or account.reserved < reservation.reserved_credits:
        raise CreditRejected("credit reservation is inconsistent")
    account.reserved -= reservation.reserved_credits
    account.available += reservation.reserved_credits - total
    account.spent += total
    reservation.charged_credits = total
    reservation.settled_at = utcnow()
    session.add(AuditEvent(organization_id=scan.organization_id, scan_id=scan.id,
                           actor_id="credit-ledger", action="credits.settled",
                           payload={"charged": total,
                                    "refunded": reservation.reserved_credits - total}))
    return total


def release_scan_credits(session: Session, scan: Scan) -> int:
    reservation = session.scalar(select(ScanCreditReservation).where(
        ScanCreditReservation.scan_id == scan.id,
        ScanCreditReservation.organization_id == scan.organization_id).with_for_update())
    if reservation is None or reservation.released_at is not None or reservation.settled_at is not None:
        return 0
    account = session.scalar(select(OrganizationCreditAccount).where(
        OrganizationCreditAccount.organization_id == scan.organization_id).with_for_update())
    if account is None or account.reserved < reservation.reserved_credits:
        raise CreditRejected("credit reservation is inconsistent")
    account.reserved -= reservation.reserved_credits
    account.available += reservation.reserved_credits - reservation.metered_credits
    account.spent += reservation.metered_credits
    reservation.charged_credits = reservation.metered_credits
    reservation.released_at = utcnow()
    session.add(AuditEvent(organization_id=scan.organization_id, scan_id=scan.id,
                           actor_id="credit-ledger", action="credits.released",
                           payload={"charged": reservation.metered_credits,
                                    "refunded": reservation.reserved_credits - reservation.metered_credits}))
    return reservation.reserved_credits - reservation.metered_credits
