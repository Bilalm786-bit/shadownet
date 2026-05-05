"""
ShadowNet — Investigation API Routes (v2 — Enhanced Person Investigation)
Three investigation endpoints: Person (with structured seed data), Network, Website.
"""

from fastapi import APIRouter, Depends, HTTPException
from app.core.security import get_current_user
from app.services.investigation_orchestrator import orchestrator
import structlog

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/investigate", tags=["Investigation"])


@router.post("/person")
async def investigate_person(
    payload: dict,
    current_user: dict = Depends(get_current_user),
):
    """Full person investigation with structured seed data.
    Runs: breach check, social media scraping, Google/Tavily search, dark web, paste sites,
    CNIC lookup, reverse WHOIS, reverse image search, stealth browser profiling.

    Input: {
        "target": "primary search term (email/username/phone/name)",
        "username": "optional specific username",
        "email": "optional email address",
        "phone": "optional phone number",
        "cnic": "optional CNIC / national ID",
        "name": "optional full name",
        "photo_url": "optional photo URL for reverse image search",
        "aliases": ["optional", "list", "of", "aliases"]
    }
    """
    target = payload.get("target", "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")

    # Extract structured seed data
    seed_data = {
        "username": payload.get("username", "").strip(),
        "email": payload.get("email", "").strip(),
        "phone": payload.get("phone", "").strip(),
        "cnic": payload.get("cnic", "").strip(),
        "name": payload.get("name", "").strip(),
        "photo_url": payload.get("photo_url", "").strip(),
        "aliases": payload.get("aliases", []),
    }
    # Remove empty values
    seed_data = {k: v for k, v in seed_data.items() if v}

    logger.info("Person investigation requested", target=target, seeds=list(seed_data.keys()))

    result = await orchestrator.investigate_person(target, seed_data=seed_data)
    return result


@router.post("/network")
async def investigate_network(
    payload: dict,
    current_user: dict = Depends(get_current_user),
):
    """Full network investigation — IP, domain, CIDR.
    Runs: VirusTotal, Censys, DNS, ports, SSL, WHOIS, Shodan, geolocation.
    Input: { "target": "IP/domain" }
    """
    target = payload.get("target", "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")

    result = await orchestrator.investigate_network(target)
    return result


@router.post("/website")
async def investigate_website(
    payload: dict,
    current_user: dict = Depends(get_current_user),
):
    """Full website investigation — URL, domain.
    Runs: tech detection, crawler, SSL, DNS, WHOIS, subdomains, Wayback, VirusTotal.
    Input: { "target": "URL/domain" }
    """
    target = payload.get("target", "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")

    result = await orchestrator.investigate_website(target)
    return result
