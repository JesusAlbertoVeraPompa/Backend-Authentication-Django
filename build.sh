#!/usr/bin/env bash
# build.sh — executed by Render on every deploy.
# Make executable: chmod +x build.sh

set -o errexit  # exit on any error

echo "📦 Installing dependencies..."
pip install -r requirements.txt

echo "🗄️  Running migrations..."
python manage.py migrate --no-input

echo "📂 Collecting static files..."
python manage.py collectstatic --no-input

echo "🔐 Seeding roles..."
python manage.py seed_roles

echo "👤 Creating admin (if env vars set)..."
python manage.py create_admin || true

echo "✅ Build complete."
