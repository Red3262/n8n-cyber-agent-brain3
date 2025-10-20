# Use an official lightweight Python image
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies needed for some Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
 && rm -rf /var/lib/apt/lists/*

# Copy just the requirements file first to leverage Docker cache
COPY requirements.txt .

# Install the Python libraries
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of our application code
COPY . .

# Set placeholder environment variables
# We will set the real values securely in Cloud Run
ENV OPENAI_API_KEY=""
ENV ABUSEIPDB_API_KEY=""
ENV VT_API_KEY=""

# Run the web server
# Gunicorn is a production-ready server, Flask is the web framework
# It will run the 'app' object from the 'main.py' file
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "main:app"]
