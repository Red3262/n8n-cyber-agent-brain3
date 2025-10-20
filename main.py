import os
import requests
from flask import Flask, request, jsonify
from crewai import Agent, Task, Crew, Process
from crewai_tools import BaseTool
from langchain_openai import ChatOpenAI
from google.cloud import secretmanager

# --- Configuration & API Key Loading ---

# Initialize Flask app
app = Flask(__name__)

# Load environment variables from .env file for local testing (if available)
# In production (Cloud Run), these will be set in the environment.
from dotenv import load_dotenv
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
    OPENAI_API_KEY = access_secret_version("OPENAI_API_KEY", GCP_PROJECT_ID)
    ABUSEIPDB_API_KEY = access_secret_version("ABUSEIPDB_API_KEY", GCP_PROJECT_ID)
    VT_API_KEY = access_secret_version("VT_API_KEY", GCP_PROJECT_ID)
else:
    print("GCP_PROJECT_ID not set. Loading from environment variables for local testing.")
    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
    ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
    VT_API_KEY = os.environ.get("VT_API_KEY")

# Set the OpenAI API key for LangChain/CrewAI
os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY

# Initialize the LLM
# Using gpt-4o-mini for a balance of speed, cost, and intelligence
llm = ChatOpenAI(model="gpt-4o-mini")

# --- Tool Definitions ---

class AbuseIPDBTool(BaseTool):
    name: str = "AbuseIPDB IP Check"
    description: str = "Checks an IP address against the AbuseIPDB database for malicious reports. Input must be a single, valid IP address."

    def _run(self, ip: str) -> str:
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
            return response.json()
        except requests.exceptions.RequestException as e:
            return f"Error calling AbuseIPDB API: {e}"

class VirusTotalTool(BaseTool):
    name: str = "VirusTotal IP/Domain/URL Check"
    description: str = "Checks an IP address, domain, or URL against VirusTotal. Input must be a single indicator."

    def _run(self, indicator: str) -> str:
        if not VT_API_KEY:
            return "Error: VirusTotal API key is not configured."

        # Basic check to see if it's an IP, domain, or URL. This is simplified.
        # A more robust solution would use regex.
        if '.' in indicator and '/' not in indicator:
             # Could be IP or domain
             resource_type = 'ip_addresses' if all(c.isdigit() or c == '.' for c in indicator) else 'domains'
        else:
             # Simplified assumption: treat as URL, but VT API needs URL ID.
             # For simplicity, we'll just support IP and domain for now.
             resource_type = 'ip_addresses' if all(c.isdigit() or c == '.' for c in indicator) else 'domains'
             if resource_type == 'domains' and '/' in indicator:
                 return "Error: URL analysis requires URL scanning, which is a different endpoint. Please provide just an IP or domain."

        url = f"https://www.virustotal.com/api/v3/{resource_type}/{indicator}"
        headers = {
            "accept": "application/json",
            "x-apikey": VT_API_KEY
        }
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return f"Error calling VirusTotal API: {e}"

# Instantiate tools
abuseipdb_tool = AbuseIPDBTool()
virustotal_tool = VirusTotalTool()

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
    tools=[abuseipdb_tool, virustotal_tool],
    llm=llm,
    verbose=True
)

# Analysis Agent
analysis_agent = Agent(
    role='Senior Security Analyst',
    goal='Analyze the collected data to determine the threat level and provide a recommendation.',
    backstory='You are a seasoned Level 3 analyst. You correlate data from multiple sources to paint a clear picture. You determine the risk (Low, Medium, High, Critical) and advise on the next steps (e.g., "Block", "Monitor", "False Positive").',
    llm=llm,
    verbose=True
)

# Reporting Agent
reporting_agent = Agent(
    role='SOC Reporting Manager',
    goal='Create a concise, structured JSON report of the findings for the n8n workflow.',
    backstory='You are a manager who writes final reports. You must summarize the investigation into a clean JSON format. The JSON must include: "ioc", "risk_score", "summary", and "raw_data". The risk_score MUST be one of: Low, Medium, High, or Critical.',
    llm=llm,
    verbose=True
)

# --- Task Definitions ---

def create_crew(alert_data):
    # 1. Triage Task
    triage_task = Task(
        description=f'Parse this raw alert data and extract the primary IOC (IP address, domain, or hash) to investigate: {alert_data}',
        expected_output='A string containing only the single, most important IOC to investigate. For example: "1.2.3.4" or "evil-domain.com"',
        agent=triage_agent
    )

    # 2. Intelligence Task
    intelligence_task = Task(
        description='Gather threat intelligence on the IOC provided by the Triage Specialist.',
        expected_output='A consolidated JSON object containing all raw data collected from AbuseIPDB, VirusTotal, and other tools.',
        agent=intelligence_agent,
        context=[triage_task] # This task depends on the output of the triage task
    )

    # 3. Analysis Task
    analysis_task = Task(
        description=f'Analyze the intelligence data. Determine a final risk score (Low, Medium, High, or Critical) and write a short summary for the human analyst. Initial alert for context: {alert_data}',
        expected_output='A Python dictionary containing "risk_score" and "summary".',
        agent=analysis_agent,
        context=[intelligence_task] # This task depends on the output of the intelligence task
    )

    # 4. Reporting Task
    reporting_task = Task(
        description='Compile all information into a final JSON report. The IOC must be from the Triage task, the analysis from the Analysis task, and the raw data from the Intelligence task.',
        expected_output='A single, clean JSON object formatted as specified in your role.',
        agent=reporting_agent,
        context=[triage_task, intelligence_task, analysis_task], # This task uses all previous outputs
        output_json=True # Specify that the output should be JSON
    )

    # Create and run the crew
    security_crew = Crew(
        agents=[triage_agent, intelligence_agent, analysis_agent, reporting_agent],
        tasks=[triage_task, intelligence_task, analysis_task, reporting_task],
        process=Process.sequential,
        verbose=2
    )

    result = security_crew.kickoff()
    return result

# --- Flask Web Server Routes ---

@app.route('/analyze', methods=['POST'])
def analyze_endpoint():
    """
    Main endpoint that n8n will call.
    Expects JSON: { "alert_data": "..." }
    """
    if not request.json or 'alert_data' not in request.json:
        return jsonify({"error": "Invalid input. 'alert_data' key is required."}), 400

    alert_data = request.json['alert_data']

    try:
        # Run the CrewAI investigation
        result = create_crew(alert_data)

        # The result from the reporting_agent should be a JSON object
        return jsonify(result), 200

    except Exception as e:
        print(f"Error during crew kickoff: {e}")
        return jsonify({"error": f"An internal error occurred: {e}"}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """A simple health check endpoint."""
    return jsonify({"status": "healthy"}), 200

if __name__ == "__main__":
    # This allows running the app locally for testing
    # e.g., python main.py
    # The Cloud Run CMD will use gunicorn instead
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
