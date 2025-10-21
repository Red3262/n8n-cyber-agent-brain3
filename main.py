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
    # OPENAI_API_KEY removed    ABUSEIPDB_API_KEY = access_secret_version("ABUSEIPDB_API_KEY", GCP_PROJECT_ID)
    # OPENAI_API_KEY removed    ABUSEIPDB_API_KEY = access_secret_version("ABUSEIPDB_API_KEY", GCP_PROJECT_ID)
    # OPENAI_API_KEY removed    ABUSEIPDB_API_KEY = access_secret_version("ABUSEIPDB_API_KEY", GCP_PROJECT_ID)
    # OPENAI_API_KEY removed    ABUSEIPDB_API_KEY = access_secret_version("ABUSEIPDB_API_KEY", GCP_PROJECT_ID)
    # OPENAI_API_KEY removed    ABUSEIPDB_API_KEY = access_secret_version("ABUSEIPDB_API_KEY", GCP_PROJECT_ID)
    # OPENAI_API_KEY removed    ABUSEIPDB_API_KEY = access_secret_version("ABUSEIPDB_API_KEY", GCP_PROJECT_ID)
    # OPENAI_API_KEY removed    ABUSEIPDB_API_KEY = access_secret_version("ABUSEIPDB_API_KEY", GCP_PROJECT_ID)
    # OPENAI_API_KEY removed    ABUSEIPDB_API_KEY = access_secret_version("ABUSEIPDB_API_KEY", GCP_PROJECT_ID)
    # OPENAI_API_KEY removed    ABUSEIPDB_API_KEY = access_secret_version("ABUSEIPDB_API_KEY", GCP_PROJECT_ID)
    # OPENAI_API_KEY removed    ABUSEIPDB_API_KEY = access_secret_version("ABUSEIPDB_API_KEY", GCP_PROJECT_ID)
    # OPENAI_API_KEY removed    ABUSEIPDB_API_KEY = access_secret_version("ABUSEIPDB_API_KEY", GCP_PROJECT_ID)
    VT_API_KEY = access_secret_version("VT_API_KEY", GCP_PROJECT_ID)
import os
from flask import Flask, request, jsonify
from crewai import Agent, Task, Crew
from crewai_tools import SerperDevTool, WebsiteSearchTool

# Initialize Flask app
app = Flask(__name__)

# --- Environment Variable Setup ---
# In a real application, these should be set in your Cloud Run service configuration,
# preferably by linking them from Google Secret Manager.
os.environ = os.environ.get("OPENAI_API_KEY", "YOUR_OPENAI_API_KEY_HERE")
os.environ = os.environ.get("SERPER_API_KEY", "YOUR_SERPER_API_KEY_HERE")

# --- Initialize Tools ---
search_tool = SerperDevTool()
web_search_tool = WebsiteSearchTool()

# --- Define CrewAI Agents ---

# Agent 1: Security Analyst
security_analyst = Agent(
    role='Senior Security Analyst',
    goal='Investigate security alerts to determine if they represent a real threat',
    backstory='''You are a seasoned security analyst with expertise in threat intelligence.
    You use your skills to analyze IP addresses, domain names, and other indicators of compromise
    to provide a clear assessment of potential threats.''',
    verbose=True,
    allow_delegation=False,
    tools=[search_tool, web_search_tool]
)

# Agent 2: Report Formatter
report_formatter = Agent(
    role='Report Formatter',
    goal='Format the investigation findings into a structured and clean JSON report',
    backstory='''You are a meticulous assistant who takes technical findings and organizes
    them into a clean, easy-to-read JSON format. You focus on clarity and structure,
    ensuring all key findings are included in the final output.''',
    verbose=True,
    allow_delegation=False
)

# --- Define CrewAI Tasks ---

def create_analysis_tasks(ip_address, event_type, source):
    """Creates the analysis and reporting tasks for the crew."""

    investigation_task = Task(
        description=f"""
        Investigate the IP address: {ip_address}.
        The alert is of type '{event_type}' and originated from '{source}'.
        1. Use your search tools to find information about this IP address.
        2. Determine if it is a known malicious actor, a TOR exit node, a VPN, or a regular IP.
        3. Summarize your findings, including any associated threats, reputation, and geolocation.
        4. Provide a clear recommendation on whether this IP should be blocked.
        """,
        expected_output='A detailed analysis of the IP address, its reputation, associated threats, and a final recommendation.',
        agent=security_analyst
    )

    reporting_task = Task(
        description="""
        Format the security analyst's investigation findings into a structured JSON report.
        The JSON should include the following keys:
        - 'ip_address': The IP that was investigated.
        - 'is_threat': A boolean value (true or false).
        - 'threat_level': A string ('low', 'medium', 'high', 'critical').
        - 'summary': A brief summary of the findings.
        - 'recommendation': The analyst's recommendation (e.g., 'Block IP', 'Monitor', 'No action needed').
        - 'raw_findings': The detailed, unformatted findings from the analyst.
        """,
        expected_output='A JSON object containing the structured report of the security investigation.',
        agent=report_formatter,
        context=[investigation_task]
    )

    return [investigation_task, reporting_task]

# --- Flask API Endpoints ---

@app.route('/health', methods=)
def health_check():
    """A simple health check endpoint."""
    return '', 204

@app.route('/analyze', methods=)
def analyze_alert():
    """
    Main endpoint to receive alert data and trigger the CrewAI investigation.
    Expects a JSON body like:
    {
        "alert_data": {
            "ip": "8.8.8.8",
            "event_type": "SSH Alert",
            "source": "Manual Test"
        }
    }
    """
    data = request.get_json()

    if not data or 'alert_data' not in data:
        return jsonify({"error": "Invalid request body. 'alert_data' key is missing."}), 400

    alert_data = data['alert_data']
    ip_address = alert_data.get('ip')
    event_type = alert_data.get('event_type', 'Unknown Event')
    source = alert_data.get('source', 'Unknown Source')

    if not ip_address:
        return jsonify({"error": "'ip' not found in alert_data."}), 400

    try:
        # Create tasks for the crew
        tasks = create_analysis_tasks(ip_address, event_type, source)

        # Create and run the crew
        security_crew = Crew(
            agents=[security_analyst, report_formatter],
            tasks=tasks,
            verbose=2
        )

        result = security_crew.kickoff()

        return jsonify({"analysis_report": result})

    except Exception as e:
        # Log the full error for debugging in Cloud Run logs
        print(f"An error occurred during crew execution: {e}")
        return jsonify({"error": "An internal error occurred during analysis."}), 500

# --- Main Execution Block ---

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port, debug=True)
