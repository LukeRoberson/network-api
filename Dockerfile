# Use the official Python image from the Docker Hub
FROM python:3.12.7-slim
LABEL maintainer="Luke Robertson <lrobertson@lakemac.nsw.gov.au>"

# Manage packages for security
RUN apt-get update
RUN apt-get upgrade -y

# Install the necessary system libraries for uWSGI (required for slim and alpine images)
RUN apt-get install build-essential -y

# Create non-root user with no password
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt requirements.txt
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN pip install uwsgi==2.0.26

# Copy the rest of the application code
COPY . .

# Change ownership of the application code to the non-root user
RUN chown -R appuser:appgroup /app

# Switch to the non-root user
USER appuser

# uWSGI configuration
CMD ["uwsgi", \
    "--ini", "uwsgi.ini"]
