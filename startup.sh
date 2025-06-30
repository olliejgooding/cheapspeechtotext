#!/bin/bash

echo "=== Starting Azure App Service ==="

# Install system dependencies
echo "Installing system dependencies..."
apt-get update && apt-get install -y ffmpeg

# Upgrade pip
echo "Upgrading pip..."
python -m pip install --upgrade pip

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Test basic import (without database initialization for now)
echo "Testing app import..."
python -c "
try:
    print('Testing Python import...')
    from app import app
    print('✓ App imported successfully')
except Exception as e:
    print(f'✗ Import error: {e}')
    exit(1)
"

# Start the application
echo "Starting Gunicorn server..."
exec gunicorn --bind=0.0.0.0:8000 --timeout 600 --workers=1 app:app
