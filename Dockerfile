# Use official Python 3.12 slim base image
FROM python:3.12-slim

# Set working directory inside the container
WORKDIR /app

# Install system dependencies needed for compiling Python packages (like cryptography and netmiko)
RUN apt-get update && apt-get install -y \
    build-essential \
    libmariadb-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file first to utilize Docker build cache layers
COPY requirements.txt .

# Install Python packages
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application files
COPY . .

# Expose Web Port (5000) and Syslog Port (514 UDP)
EXPOSE 5000
EXPOSE 514/udp

# Run the system using python main.py (starts DB init, syslog server, web dashboard, and collector loop)
CMD ["python", "main.py"]
