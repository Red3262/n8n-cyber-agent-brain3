-=import os
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
import os
from flask import Flask, request, jsonify
# from crewai import Agent, Task, Crew, Process
# from crewai_tools import SerperDevTool, ScrapeWebsiteTool # Example tools
# from google.cloud import secretmanager # For getting secrets later

# --- Environment Variable Setup ---
# Attempt to load API keys from .env file for local dev (optional)
# from dotenv import load_dotenv
# load_dotenv() 

# Get API Keys securely from environment variables (essential for Cloud Run)
# These will be set by Cloud Run later, using Secret Manager
openai_api_key = os.environ.get("OPENAI_API_KEY", "YOUR_OPENAI_KEY_FALLBACK_IF_NEEDED") 
# abuseipdb_api_key = os.environ.get("ABUSEIPDB_API_KEY") 
# vt_api_key = os.environ.get("VT_API_KEY")

# --- Flask Web Server Setup ---
app = Flask(__name__)

# --- CrewAI Agent Setup (Placeholder) ---
# TODO: Define Agents (Triage, Intelligence, Analysis)
# TODO: Define Tools (using API keys)
# TODO: Define Tasks
# TODO: Define Crew

# --- Webhook Endpoint ---
@app.route('/run-agent', methods=['POST'])
def handle_webhook():
    """Receives alert data from n8n, runs the agent, returns result."""
    if not request.json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.json
    # --- Updated to handle n8n's data structure ---
    # Expecting n8n to send: {"ioc_type": "IP", "value": "1.2.3.4"}
    ioc_type = data.get('ioc_type')
    value = data.get('value')
    # --- End Update ---

    if not ioc_type or not value:
        return jsonify({"error": "Missing 'ioc_type' or 'value' in JSON body"}), 400

    print(f"Received alert: Type={ioc_type}, Value={value}") # Log for debugging

    # --- Placeholder for CrewAI Execution ---
    # result_text = f"Agent would investigate {ioc_type}: {value}" 
    # For now, just echo back the input
    result_json = {
        "risk_score": "Placeholder",
        "summary": f"Placeholder summary for {ioc_type}: {value}",
        "recommendation": "Placeholder recommendation"
    }
    # ----------------------------------------

    # TODO: Implement actual crew.kickoff() here
    # try:
    #     # security_crew = Crew(...) 
    #     # result = security_crew.kickoff(inputs={'ioc_type': ioc_type, 'value': value})
    #     # result_json = parse_agent_output(result) # Need a function to parse CrewAI output to JSON
    #     pass 
    # except Exception as e:
    #     print(f"Error running crew: {e}")
    #     return jsonify({"error": "Agent execution failed"}), 500

    print(f"Sending result: {result_json}") # Log for debugging
    return jsonify(result_json)

# --- Health Check Endpoint (FIXED) ---
@app.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint."""
    return jsonify({"status": "healthy"}), 200

# --- Main Execution ---
if __name__ == "__main__":
    server_port = int(os.environ.get("PORT", 8080))
    app.run(debug=False, port=server_port, host='0.0.0.0')
