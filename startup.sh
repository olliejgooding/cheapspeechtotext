#!/bin/bash
echo "Starting Azure App Service startup script..."
apt-get update && apt-get install -y ffmpeg
python -m pip install --upgrade pip
pip install -r requirements.txt
python -c "
try:
    from app import init_db
    init_db()
    print('Database initialized successfully')
except Exception as e:
    print(f'Database initialization error: {e}')
"
exec gunicorn --bind=0.0.0.0:8000 --timeout 600 --workers=2 --worker-class=sync app:app