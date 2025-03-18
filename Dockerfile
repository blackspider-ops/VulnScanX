# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Install nmap
RUN apt-get update && apt-get install -y nmap

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Expose any necessary ports (if needed for testing)
EXPOSE 8080

# Command to run your application (adjust if necessary)
CMD ["python", "scanner.py"]
