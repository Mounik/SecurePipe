FROM python:3.11-slim

# 🚨 HADOLINT: Running as root
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .

# 🚨 HADOLINT: No healthcheck, latest tag, no USER directive
EXPOSE 5000
CMD ["python", "app.py"]