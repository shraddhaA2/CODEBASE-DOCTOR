import json
import logging
from typing import Any
import httpx
from pydantic import ValidationError
from app.config import settings
from app.ai.prompts import SYSTEM_PROMPT, DIAGNOSIS_USER_PROMPT, PATCH_USER_PROMPT
from app.ai.schemas import DiagnosisResult, PatchResult

logger = logging.getLogger("codebase_doctor.ai")


class AiNotConfiguredError(Exception):
    """Raised when an AI operation is requested but LLM settings are absent."""
    pass


class AiValidationError(Exception):
    """Raised when LLM response repeatedly fails schema validation."""
    pass


class AiClient:
    def __init__(self):
        self.base_url = (settings.LLM_BASE_URL or "https://api.openai.com/v1").rstrip("/")
        self.api_key = settings.LLM_API_KEY
        self.model = settings.LLM_MODEL

    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def _post_chat_completion(self, messages: list[dict[str, str]]) -> str:
        """Execute chat completion request against OpenAI-compatible API."""
        if not self.is_configured():
            raise AiNotConfiguredError(
                "AI is not configured. Please set LLM_API_KEY, LLM_BASE_URL, and LLM_MODEL in .env"
            )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            return content

    async def generate_diagnosis(self, evidence_pack: dict[str, Any]) -> tuple[DiagnosisResult, str]:
        """Generate structured diagnosis with 1 validation retry."""
        user_prompt = DIAGNOSIS_USER_PROMPT.replace(
            "{evidence_json}", json.dumps(evidence_pack, indent=2)
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        raw_output = await self._post_chat_completion(messages)

        try:
            validated = DiagnosisResult.model_validate_json(raw_output)
            return validated, raw_output
        except (ValidationError, json.JSONDecodeError) as e:
            logger.warning(f"AI diagnosis output failed validation on first pass: {e}. Retrying once...")
            # Retry once with feedback
            retry_messages = list(messages)
            retry_messages.append({"role": "assistant", "content": raw_output})
            retry_messages.append({
                "role": "user",
                "content": f"Your previous output failed validation with error: {e}. Please fix and return strictly valid JSON matching the schema."
            })
            second_output = await self._post_chat_completion(retry_messages)
            try:
                validated = DiagnosisResult.model_validate_json(second_output)
                return validated, second_output
            except Exception as e2:
                raise AiValidationError(f"AI response failed schema validation after retry: {e2}")

    async def generate_patches(self, evidence_pack: dict[str, Any]) -> tuple[PatchResult, str]:
        """Generate structured patch proposals with 1 validation retry."""
        user_prompt = PATCH_USER_PROMPT.replace(
            "{evidence_json}", json.dumps(evidence_pack, indent=2)
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        raw_output = await self._post_chat_completion(messages)

        try:
            validated = PatchResult.model_validate_json(raw_output)
            return validated, raw_output
        except (ValidationError, json.JSONDecodeError) as e:
            logger.warning(f"AI patch output failed validation on first pass: {e}. Retrying once...")
            retry_messages = list(messages)
            retry_messages.append({"role": "assistant", "content": raw_output})
            retry_messages.append({
                "role": "user",
                "content": f"Your previous output failed validation with error: {e}. Please fix and return strictly valid JSON matching the schema."
            })
            second_output = await self._post_chat_completion(retry_messages)
            try:
                validated = PatchResult.model_validate_json(second_output)
                return validated, second_output
            except Exception as e2:
                raise AiValidationError(f"AI patch proposal failed schema validation after retry: {e2}")
