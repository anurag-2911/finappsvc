# Use the official Python image
FROM python:3.9

# Set the working directory
WORKDIR /app

# Copy the current directory contents into the container
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Start FastAPI using Uvicorn
CMD ["uvicorn", "authsvc:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
