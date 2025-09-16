"""
AI-powered Vulnerability Validator
"""

import os
import json
import logging
from typing import Dict, Any
import openai
from app.config import Config

logger = logging.getLogger(__name__)

class AIValidator:
    """AI-powered vulnerability validator"""

    def __init__(self):
        openai.api_key = Config.OPENAI_API_KEY

    def _build_prompt(self, vulnerability_data: Dict[str, Any]) -> str:
        """Build the prompt for AI validation"""
        # Truncate long pieces of data to stay within token limits
        description = (vulnerability_data.get('description', '') or '')[:1000]
        evidence = (vulnerability_data.get('evidence', '') or '')[:1000]
        request_headers = str(vulnerability_data.get('request', {}).get('headers', ''))[:1000]
        request_body = str(vulnerability_data.get('request', {}).get('body', ''))[:1000]
        response_headers = str(vulnerability_data.get('response', {}).get('headers', ''))[:1000]
        response_body = str(vulnerability_data.get('response', {}).get('body', ''))[:1000]

        prompt = f"""
You are an expert cybersecurity analyst. Your task is to analyze a potential vulnerability found by an automated scanner and determine the likelihood that it is a true positive.

**Vulnerability Details:**
- **Name:** {vulnerability_data.get('name', 'N/A')}
- **Description:** {description}
- **Category:** {vulnerability_data.get('category', 'N/A')}
- **Tool:** {vulnerability_data.get('tool', 'N/A')}
- **Raw Evidence:** {evidence}

**HTTP Request:**
- **URL:** {vulnerability_data.get('request', {}).get('url', 'N/A')}
- **Method:** {vulnerability_data.get('request', {}).get('method', 'N/A')}
- **Headers:**
{request_headers}
- **Body:**
{request_body}

**HTTP Response:**
- **Status Code:** {vulnerability_data.get('response', {}).get('status_code', 'N/A')}
- **Headers:**
{response_headers}
- **Body:**
{response_body}

**Analysis Task:**
Based on all the information provided, please perform the following:
1.  **Analyze the evidence:** Is the request and response pair indicative of the vulnerability described?
2.  **Assess confidence:** How likely is this a true positive, not a false positive from the automated scanner?
3.  **Provide a brief justification:** Explain your reasoning in 1-2 sentences.

**Output Format:**
Provide your response as a JSON object with the following keys:
- "confidence": A string, either "High", "Medium", "Low", or "Uncertain".
- "analysis": A string containing your brief justification.

Example:
{{
  "confidence": "High",
  "analysis": "The response body contains a reflected parameter with an XSS payload, and the Content-Type is text/html, indicating a high likelihood of a true positive."
}}
"""
        return prompt

    def _parse_ai_response(self, content: str) -> Dict[str, Any]:
        """Parse the AI JSON response"""
        try:
            # The response might be inside a markdown code block
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]

            data = json.loads(content)
            return {
                'confidence': data.get('confidence', 'Uncertain'),
                'analysis': data.get('analysis', 'Could not parse AI response.')
            }
        except (json.JSONDecodeError, IndexError) as e:
            logger.warning(f"Failed to parse AI response JSON: {e}. Raw content: {content}")
            return {
                'confidence': 'Uncertain',
                'analysis': f"Error parsing AI response. Raw output: {content[:200]}..."
            }

    def validate_vulnerability(self, vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate a vulnerability using an AI model to determine if it's a true positive.
        """
        if not openai.api_key:
            logger.warning("OPENAI_API_KEY not set. Skipping AI validation.")
            return {
                'confidence': 'Unavailable',
                'analysis': 'OpenAI API key not configured.'
            }

        try:
            prompt = self._build_prompt(vulnerability_data)

            client = openai.OpenAI(api_key=Config.OPENAI_API_KEY)
            response = client.chat.completions.create(
                model=Config.OPENAI_MODEL,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a helpful cybersecurity analyst who provides responses in JSON format."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=500,
                temperature=0.2,
                response_format={"type": "json_object"} # Use JSON mode if available
            )

            content = response.choices[0].message.content
            return self._parse_ai_response(content)

        except Exception as e:
            logger.error(f"Error during AI vulnerability validation: {e}")
            return {
                'confidence': 'Error',
                'analysis': f"An exception occurred during validation: {str(e)}"
            }
