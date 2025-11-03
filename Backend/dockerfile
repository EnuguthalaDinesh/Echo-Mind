# Dockerfile
# Use a slim Python image for a smaller footprint
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED 1
ENV APP_HOME /usr/src/app
WORKDIR $APP_HOME

# Install system dependencies needed for some Python packages (e.g., if needed by motor or passlib, though often not on slim)
# Add this line if you encounter build errors related to missing system libraries
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     build-essential \
#     && rm -rf /var/lib/apt/lists/*

# Copy requirements file and install dependencies
COPY requirements.txt .
# Install packages, explicitly ignoring cached files to save space
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port (Render will use this)
EXPOSE 8000

# Command to run the application using Gunicorn for production
# Gunicorn is generally preferred over a simple uvicorn run command in production
# Since the code uses a simple 'uvicorn' for now, we'll keep it simple for Render's Web Service,
# but a full production setup should use gunicorn+uvicorn workers.
# For simplicity with Render's free tier, we'll use a straightforward uvicorn command.
# CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
# Assuming your file is named `main.py`
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]