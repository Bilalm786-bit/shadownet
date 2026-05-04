"""
ShadowNet — AI Analyst Service
Uses ChatGPT 5.5 for intelligent OSINT analysis, report summarization, and threat assessment.
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
    """AI-powered intelligence analysis using ChatGPT 5.5."""

    def __init__(self):
        self.client = None
        self.model = settings.openai_model

    def _ensure_client(self):
        if not self.client and HAS_OPENAI and settings.openai_api_key:
            self.client = AsyncOpenAI(api_key=settings.openai_api_key)

    async def analyze_scan_results(
        self, target: str, scan_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Analyze OSINT scan results and generate a threat assessment."""
        self._ensure_client()
        if not self.client:
            return {"error": "OpenAI API key not configured", "analysis": None}

        prompt = f"""You are an expert OSINT analyst and cybersecurity professional.
Analyze the following OSINT scan results for the target: {target}

SCAN RESULTS:
{json.dumps(scan_results, indent=2, default=str)[:8000]}

Provide a comprehensive analysis including:
1. **Executive Summary**: Brief overview of findings
2. **Risk Assessment**: Overall threat level (Critical/High/Medium/Low) with justification
3. **Key Findings**: Most important discoveries with their implications
4. **Digital Footprint Score**: Rate the target's exposure (1-10)
5. **Attack Surface**: Potential vulnerabilities or exposure points
6. **Recommendations**: Actionable steps to reduce exposure
7. **Connections Map**: Notable relationships between discovered entities

Format your response as JSON with these keys: executive_summary, risk_level, risk_score (1-100), 
key_findings (array), digital_footprint_score, attack_surface (array), recommendations (array), connections (array)"""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are ShadowNet AI — an elite OSINT intelligence analyst. Respond only in valid JSON."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3,
                max_tokens=4000,
                response_format={"type": "json_object"},
            )
            analysis = json.loads(response.choices[0].message.content)
            logger.info("AI analysis complete", target=target, risk=analysis.get("risk_level"))
            return {"analysis": analysis, "model": self.model, "tokens_used": response.usage.total_tokens}
        except Exception as e:
            logger.error("AI analysis failed", error=str(e))
            return {"error": str(e), "analysis": None}

    async def generate_report_summary(
        self, case_name: str, all_findings: List[Dict[str, Any]]
    ) -> str:
        """Generate a professional executive summary for a pentest report."""
        self._ensure_client()
        if not self.client:
            return "AI summary unavailable — API key not configured."

        prompt = f"""Write a professional executive summary for an OSINT investigation report.

Investigation: {case_name}

Findings Overview:
{json.dumps(all_findings, indent=2, default=str)[:6000]}

Write a clear, professional, 3-5 paragraph executive summary suitable for a C-level audience.
Include: scope, key risks, notable findings, and recommended actions.
Use professional language. Do NOT use technical jargon without explanation."""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a senior cybersecurity consultant writing an executive report."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.4,
                max_tokens=2000,
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"AI summary generation failed: {str(e)}"

    async def extract_entities_from_text(self, text: str) -> List[Dict[str, str]]:
        """Use AI to extract entities (names, emails, IPs, orgs) from unstructured text."""
        self._ensure_client()
        if not self.client:
            return []

        prompt = f"""Extract all intelligence entities from the following text.
Return a JSON array of objects with keys: type, value, confidence (0-1)
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
                temperature=0.1,
                max_tokens=2000,
                response_format={"type": "json_object"},
            )
            result = json.loads(response.choices[0].message.content)
            return result.get("entities", result) if isinstance(result, dict) else result
        except Exception:
            return []

    async def correlate_entities(
        self, entities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Use AI to find hidden connections between discovered entities."""
        self._ensure_client()
        if not self.client:
            return {"correlations": []}

        prompt = f"""Analyze these OSINT entities and find potential connections, patterns, or correlations.

ENTITIES:
{json.dumps(entities, indent=2, default=str)[:6000]}

Identify:
1. Entities that likely belong to the same person/organization
2. Hidden connections (shared infrastructure, naming patterns, etc.)
3. Anomalies or suspicious patterns
4. Timeline correlations

Return JSON: {{ "correlations": [...], "patterns": [...], "anomalies": [...], "confidence_score": 0-1 }}"""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an OSINT correlation engine. Respond in JSON only."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=3000,
                response_format={"type": "json_object"},
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            return {"correlations": [], "error": str(e)}


# Singleton instance
ai_analyst = AIAnalyst()
