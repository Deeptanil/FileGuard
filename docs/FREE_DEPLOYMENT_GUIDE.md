# FileGuard — Free Deployment Guide

This guide details two 100% free deployment methods for FileGuard.

---

## Method 1: PythonAnywhere (Recommended — Persistent Free Storage)
**Why PythonAnywhere:** Free tier provides 512 MB of persistent Linux disk storage. Unlike container platforms whose files are wiped on server restart, your SQLite database and `storage/` directory remain intact.

### Step-by-Step Instructions:
1. **Create an Account:**
   Sign up at [pythonanywhere.com](https://www.pythonanywhere.com) (no credit card required).

2. **Open a Bash Console:**
   From your dashboard, click **"Consoles"** -> **"Bash"**.

3. **Clone or Upload Your Code:**
   In the Bash console, clone your GitHub repository:
   ```bash
   git clone https://github.com/your-username/FileGuard.git
   cd FileGuard
   ```

4. **Create a Virtual Environment & Install Dependencies:**
   ```bash
   python3.10 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   python scripts/init_db.py
   ```

5. **Configure Web App in Dashboard:**
   - Go to the **"Web"** tab.
   - Click **"Add a new web app"** -> **"Manual configuration"** -> Select **Python 3.10**.
   - Under **"Virtualenv"**, enter: `/home/yourusername/FileGuard/venv`.
   - Under **"Code"**:
     - Working directory: `/home/yourusername/FileGuard`
   - Click on the **"WSGI configuration file"** link and replace its contents with:
     ```python
     import sys
     import os

     path = '/home/yourusername/FileGuard'
     if path not in sys.path:
         sys.path.append(path)

     from app import create_app
     application = create_app()
     ```
   - Click **"Save"** and then **"Reload yourusername.pythonanywhere.com"**.

Your website will be live at: `https://yourusername.pythonanywhere.com`

---

## Method 2: Render.com (Free Web Service via GitHub)
**Why Render:** Free automated deployments directly from your GitHub repository with HTTPS out of the box.

### Step-by-Step Instructions:
1. Push your `FileGuard` project to GitHub.
2. Sign up for free at [render.com](https://render.com).
3. Click **"New +"** -> **"Web Service"**.
4. Connect your GitHub repository.
5. Configure the deployment settings:
   - **Environment:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt && python scripts/init_db.py`
   - **Start Command:** `gunicorn wsgi:app`
   - **Instance Type:** `Free`
6. Under **"Environment Variables"**, add:
   - `FLASK_ENV`: `production`
   - `FLASK_DEBUG`: `False`
   - `SECRET_KEY`: *(click generate or enter random secret)*
   - `EXPIRATION_HOURS`: `12`
   - `ADMIN_USERNAME`: `admin`
   - `ADMIN_PASSWORD`: `FileGuard@Sec2026!`
7. Click **"Create Web Service"**.

Your application will deploy and provide an `https://fileguard-app.onrender.com` URL with free SSL.

