import logging
import os
import re

try:
    import google.generativeai as genai
    HAS_GEMINI = True
except ImportError:
    HAS_GEMINI = False

log = logging.getLogger(__name__)

from os_tests.libs.utils_lib import get_cfg

def analyze_failure(failure_content, api_key=None, model_name=None, http_proxy=None, https_proxy=None):
    if model_name is None:
        params = get_cfg()
        model_name = params.get('gemini_model_name', 'gemini-2.5-flash')
    if "AssertionError" not in failure_content:
        return "No AssertionError found in failure logs, skip analysis."

    if not HAS_GEMINI:
        return "Google Gemini SDK not installed. Please install 'google-generativeai' (pip install google-generativeai)."

    if not api_key:
        return "Gemini API key not provided."

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
"""

        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        log.error(f"Error analyzing with Gemini: {e}")
        return f"Error analyzing with Gemini: {e}"
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
