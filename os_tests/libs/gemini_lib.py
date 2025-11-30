import logging
import os
import re

import google.generativeai as genai

log = logging.getLogger(__name__)
# Ensure INFO messages from this logger are always processed
log.setLevel(logging.INFO)

from os_tests.libs.utils_lib import get_cfg

def analyze_failure(failure_content, api_key=None, model_name=None, http_proxy=None, https_proxy=None):
    if model_name is None:
        params = get_cfg()
        model_name = params.get('gemini_model_name', 'gemini-2.5-flash')
    if "AssertionError" not in failure_content:
        return {
            "category": "N/A",
            "confidence": "N/A",
            "analysis": "No AssertionError found in failure logs, skip analysis."
        }

    if not api_key:
        return {
            "category": "N/A",
            "confidence": "N/A",
            "analysis": "Gemini API key not provided."
        }

    # Store original environment variables
    original_http_proxy = os.environ.get('http_proxy')
    original_https_proxy = os.environ.get('https_proxy')

    try:
        # Set proxy if provided
        if http_proxy:
            os.environ['http_proxy'] = http_proxy
        if https_proxy:
            os.environ['https_proxy'] = https_proxy

        genai.configure(api_key=api_key)
        # Use the specified model, defaulting to gemini-pro
        model = genai.GenerativeModel(model_name)

        # Extract relevant information
        key_steps = "N/A"
        expect_result = "N/A"

        # Regex to match indented block following the key
        key_steps_match = re.search(r"key_steps:\s*\n((?:[ \t]+.*\n?)+)", failure_content)
        if key_steps_match:
            key_steps = key_steps_match.group(1).strip()

        expect_result_match = re.search(r"expect_result:\s*\n((?:[ \t]+.*\n?)+)", failure_content)
        if expect_result_match:
            expect_result = expect_result_match.group(1).strip()

        # Extract AssertionError content
        assertion_match = re.search(r"(AssertionError:.*)", failure_content, re.DOTALL)
        if assertion_match:
            assertion_content = assertion_match.group(1)
            # Limit assertion content size to avoid token limits
            assertion_content = assertion_content[:10000]
        else:
            assertion_content = "AssertionError detected but extraction failed."

        prompt = f"""The following is a test failure log from os-tests suite.

Test Steps:
{key_steps}

Expected Result:
{expect_result}

Error Log:
{assertion_content}

Please analyze the failure in the context of the steps and expected result. Explain what the AssertionError means and suggest possible root causes and solutions.
Finally, categorize the issue as one of the following: 'Environment Issue', 'Test Code Issue', or 'Product Issue'. Also, indicate your confidence level (0-100%) in this assessment.
Format your answer as:
Category: [Category]
Confidence: [Confidence%]
Analysis: [Your detailed analysis]
"""

        response = model.generate_content(prompt)
        analysis_text = response.text

        category = "Unknown"
        confidence = 0
        analysis = analysis_text

        category_match = re.search(r"Category: (.*)", analysis_text)
        if category_match:
            category = category_match.group(1).strip()

        confidence_match = re.search(r"Confidence: (\d+)%", analysis_text)
        if confidence_match:
            confidence = int(confidence_match.group(1))

        # Try to find a specific "Analysis:" section
        analysis_match = re.search(r"Analysis:\s*\n(.*)", analysis_text, re.DOTALL)
        if analysis_match:
            analysis = analysis_match.group(1).strip()
        else:
            # Fallback to previous logic if no "Analysis:" header
            analysis_parts = re.split(r"Category:.*|Confidence:.*", analysis_text, flags=re.DOTALL)
            if len(analysis_parts) > 2:
                analysis = analysis_parts[2].strip()
            elif len(analysis_parts) > 0:
                analysis = analysis_parts[-1].strip()
            # If still empty, ensure it's not just whitespace from before
            if not analysis:
                analysis = '' # Explicitly empty if nothing found by fallback

        return {
            "category": category,
            "confidence": confidence,
            "analysis": analysis
        }
    except Exception as e:
        log.error(f"Error analyzing with Gemini: {e}")
        return {
            "category": "N/A",
            "confidence": "N/A",
            "analysis": f"Error analyzing with Gemini: {e}"
        }
    finally:
        # Restore original environment variables
        if original_http_proxy is None:
            os.environ.pop('http_proxy', None)
        else:
            os.environ['http_proxy'] = original_http_proxy

        if original_https_proxy is None:
            os.environ.pop('https_proxy', None)
        else:
            os.environ['https_proxy'] = original_https_proxy
