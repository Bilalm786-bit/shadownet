"""
ShadowNet — AI Analyst Service
Uses ChatGPT for intelligent OSINT analysis, breach explanation, and threat assessment.
"""

try:
    from openai import AsyncOpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False
from app.core.config import settings
from typing import Dict, Any, List, Optional
import json
import structlog

logger = structlog.get_logger(__name__)


class AIAnalyst:
    """AI-powered intelligence analysis using ChatGPT."""

    def __init__(self):
        self.client = None
        self.model = settings.openai_model

    def _ensure_client(self):
        if not self.client and HAS_OPENAI and settings.openai_api_key:
            self.client = AsyncOpenAI(api_key=settings.openai_api_key)

    async def analyze_scan_results(self, target: str, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze OSINT scan results and generate a threat assessment."""
        self._ensure_client()
        if not self.client:
            return {"error": "OpenAI API key not configured", "analysis": None}

        prompt = f"""You are an expert OSINT analyst. Analyze these scan results for: {target}

SCAN RESULTS:
{json.dumps(scan_results, indent=2, default=str)[:8000]}

Provide analysis as JSON:
{{
  "executive_summary": "...",
  "risk_level": "Critical/High/Medium/Low",
  "risk_score": 0-100,
  "key_findings": ["..."],
  "digital_footprint_score": 1-10,
  "attack_surface": ["..."],
  "recommendations": ["..."],
  "connections": ["..."]
}}"""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are ShadowNet AI — an elite OSINT analyst. Respond only in valid JSON."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3, max_tokens=4000,
                response_format={"type": "json_object"},
            )
            analysis = json.loads(response.choices[0].message.content)
            return {"analysis": analysis, "model": self.model, "tokens_used": response.usage.total_tokens}
        except Exception as e:
            logger.error("AI analysis failed", error=str(e))
            return {"error": str(e), "analysis": None}

    async def explain_breach(self, target: str, breaches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """AI explains HOW each breach occurred — timeline, method, impact."""
        self._ensure_client()
        if not self.client:
            return [{"error": "AI unavailable"}]

        prompt = f"""You are a cybersecurity breach analyst. For the target "{target}", explain HOW each breach occurred.

BREACH DATA:
{json.dumps(breaches[:10], indent=2, default=str)[:6000]}

For EACH breach, provide:
1. **What happened** — the breach event
2. **How it was breached** — attack vector (SQL injection, phishing, insider, credential stuffing, etc.)
3. **What data was exposed** — specific data types
4. **Impact** — how this affects the target
5. **Timeline** — when it happened and when discovered
6. **Dark web status** — whether this data is actively traded

Return JSON:
{{
  "breach_explanations": [
    {{
      "breach_name": "...",
      "what_happened": "...",
      "attack_vector": "...",
      "data_exposed": ["..."],
      "impact_assessment": "...",
      "timeline": "...",
      "dark_web_status": "...",
      "severity": "critical/high/medium/low"
    }}
  ]
}}"""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a breach forensics expert. Respond in valid JSON."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3, max_tokens=4000,
                response_format={"type": "json_object"},
            )
            result = json.loads(response.choices[0].message.content)
            return result.get("breach_explanations", [])
        except Exception as e:
            return [{"error": str(e)}]

    async def generate_person_dossier(self, target: str, all_data: Dict[str, Any]) -> str:
        """Generate comprehensive person intelligence dossier."""
        self._ensure_client()
        if not self.client:
            return "AI dossier unavailable."

        prompt = f"""Compile a comprehensive OSINT intelligence dossier for: {target}

DATA:
{json.dumps(all_data, indent=2, default=str)[:8000]}

Write a professional intelligence report covering:
1. Identity Summary
2. Digital Footprint
3. Social Media Presence
4. Breach History & Exposure
5. Risk Assessment
6. Recommendations

Use clear, professional language."""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an intelligence analyst writing a classified dossier."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.4, max_tokens=3000,
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Dossier generation failed: {str(e)}"

    async def generate_report_summary(self, case_name: str, all_findings: List[Dict[str, Any]]) -> str:
        """Generate a professional executive summary for a pentest report."""
        self._ensure_client()
        if not self.client:
            return "AI summary unavailable — API key not configured."

        prompt = f"""Write a professional executive summary for an OSINT investigation report.
Investigation: {case_name}
Findings: {json.dumps(all_findings, indent=2, default=str)[:6000]}
Write 3-5 paragraphs suitable for a C-level audience."""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a senior cybersecurity consultant writing an executive report."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.4, max_tokens=2000,
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"AI summary generation failed: {str(e)}"

    async def extract_entities_from_text(self, text: str) -> List[Dict[str, str]]:
        """Use AI to extract entities from unstructured text."""
        self._ensure_client()
        if not self.client:
            return []

        prompt = f"""Extract all intelligence entities from this text.
Return JSON array: [{{"type": "...", "value": "...", "confidence": 0-1}}]
Entity types: person, email, phone, ip, domain, organization, location, username, crypto_wallet

Text:
{text[:4000]}"""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "Extract entities and respond only in JSON array format."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1, max_tokens=2000,
                response_format={"type": "json_object"},
            )
            result = json.loads(response.choices[0].message.content)
            return result.get("entities", result) if isinstance(result, dict) else result
        except Exception:
            return []

    async def correlate_entities(self, entities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Use AI to find hidden connections between discovered entities."""
        self._ensure_client()
        if not self.client:
            return {"correlations": []}

        prompt = f"""Analyze these OSINT entities and find connections, patterns, or correlations.
ENTITIES: {json.dumps(entities, indent=2, default=str)[:6000]}
Return JSON: {{ "correlations": [...], "patterns": [...], "anomalies": [...], "confidence_score": 0-1 }}"""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an OSINT correlation engine. Respond in JSON only."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2, max_tokens=3000,
                response_format={"type": "json_object"},
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            return {"correlations": [], "error": str(e)}


# Singleton instance
ai_analyst = AIAnalyst()
