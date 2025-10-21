import os
import requests
from flask import Flask, request, jsonify
from crewai import Agent, Task, Crew, Process
from crewai_tools import tool # Import the decorator
from langchain_google_genai import ChatGoogleGenerativeAI # Corrected import
from google.cloud import secretmanager
from dotenv import load_dotenv # Added import for local testing

# --- Configuration & API Key Loading ---

# Initialize Flask app
app = Flask(__name__)

# Load environment variables from .env file for local testing (if available)
# In production (Cloud Run), these will be set in the environment.
load_dotenv()

def access_secret_version(secret_id, project_id, version_id="latest"):
    """
    Accesses a secret version from Google Secret Manager.
    """
    try:
        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
        response = client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8")
    except Exception as e:
        print(f"Error accessing secret {secret_id}: {e}")
        # Fallback to environment variables if Secret Manager fails
        # This allows local testing using .env files
        return os.environ.get(secret_id)

# --- API Key Setup ---
# Try to get Project ID from environment (set in Cloud Run)
GCP_PROJECT_ID = os.environ.get("GCP_PROJECT_ID")

if GCP_PROJECT_ID:
    print("Loading secrets from Google Secret Manager...")
    # OPENAI_API_KEY removed
    ABUSEIPDB_API_KEY = access_secret_version("ABUSEIPDB_API_KEY", GCP_PROJECT_ID)
    VT_API_KEY = access_secret_version("VT_API_KEY", GCP_PROJECT_ID)
else:
    print("GCP_PROJECT_ID not set. Loading from environment variables for local testing.")
    # OPENAI_API_KEY removed
    ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
    VT_API_KEY = os.environ.get("VT_API_KEY")

# OPENAI_API_KEY os.environ setting removed

# Initialize the Gemini LLM
# It will automatically use the permissions of the Cloud Run service account
llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash-latest", # Using Flash for speed and free tier
                           convert_system_message_to_human=True) # Helps with compatibility

# --- Tool Definitions ---

@tool("AbuseIPDB IP Check")
def abuseipdb_tool(ip: str) -> str:
    """Checks an IP address against the AbuseIPDB database for malicious reports.
    Input must be a single, valid IP address."""
    if not ABUSEIPDB_API_KEY:
        return "Error: AbuseIPDB API key is not configured."

    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=10)
        response.raise_for_status() # Raise an error for bad status codes
        # Attempt to return JSON, fall back to text if needed
        try:
            return response.json()
        except requests.exceptions.JSONDecodeError:
            return f"AbuseIPDB returned non-JSON response: {response.text}"
    except requests.exceptions.RequestException as e:
        return f"Error calling AbuseIPDB API: {e}"

@tool("VirusTotal IP/Domain Check")
def virustotal_tool(indicator: str) -> str:
    """Checks an IP address or domain against VirusTotal.
    Input must be a single IP or domain."""
    if not VT_API_KEY:
        return "Error: VirusTotal API key is not configured."

    # Basic check for IP vs domain (simplified)
    # Improved check for IP format
    is_ip = all(c.isdigit() or c == '.' for c in indicator) and indicator.count('.') == 3
    if '.' in indicator and '/' not in indicator:
         resource_type = 'ip_addresses' if is_ip else 'domains'
    else:
         return "Error: Please provide just an IP or domain. URL analysis is not supported by this tool."

    url = f"https://www.virustotal.com/api/v3/{resource_type}/{indicator}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        # Attempt to return JSON, fall back to text if needed
        try:
            return response.json()
        except requests.exceptions.JSONDecodeError:
            return f"VirusTotal returned non-JSON response: {response.text}"
    except requests.exceptions.RequestException as e:
        # Provide more detail on common VT errors
        if e.response is not None:
             if e.response.status_code == 404:
                 return f"Indicator {indicator} not found in VirusTotal."
             elif e.response.status_code == 401:
                 return "Error calling VirusTotal API: Invalid API Key."
             elif e.response.status_code == 429:
                 return "Error calling VirusTotal API: Rate limit exceeded."
        return f"Error calling VirusTotal API: {e}"

# --- Agent Definitions ---

# Triage Agent
triage_agent = Agent(
    role='Triage Specialist',
    goal='Parse the initial alert and extract key Indicators of Compromise (IOCs). Identify the primary IOC to investigate.',
    backstory='You are a meticulous Level 1 SOC analyst. Your job is to read raw alert data and pull out the actionable IP addresses, domains, or hashes. You only identify the IOCs, you do not analyze them.',
    llm=llm,
    verbose=True
)

# Intelligence Agent
intelligence_agent = Agent(
    role='Threat Intelligence Gatherer',
    goal='Collect data on a given IOC from all available threat intelligence feeds.',
    backstory='You are an expert in using security APIs. You take a single IOC (like an IP or domain) and query tools like AbuseIPDB and VirusTotal to get raw data.',
    tools=[abuseipdb_tool, virustotal_tool], # Correctly references the tool functions
    llm=llm,
    verbose=True,
    allow_delegation=False # Prevent this agent from trying to delegate tasks
)

# Analysis Agent
analysis_agent = Agent(
    role='Senior Security Analyst',
    goal='Analyze the collected data to determine the threat level and provide a recommendation.',
    backstory='You are a seasoned Level 3 analyst. You correlate data from multiple sources to paint a clear picture. You determine the risk (Low, Medium, High, or Critical) and advise on the next steps (e.g., "Block", "Monitor", "False Positive").',
    llm=llm,
    verbose=True,
    allow_delegation=False
)

# Reporting Agent
reporting_agent = Agent(
    role='SOC Reporting Manager',
    goal='Create a concise, structured JSON report of the findings for the n8n workflow.',
    backstory='You are a manager who writes final reports. You must summarize the investigation into a clean
