# 🛡️ PhishGuard — Phishing Website Detection Web App

A production-quality Django web application that uses a **Random Forest machine learning model** to detect phishing URLs in real time, with a sleek dark dashboard UI, scan history, user authentication, and a REST API.

---

## 📁 Project Structure

```
phishing_detector/
├── manage.py
├── requirements.txt
├── README.md
├── db.sqlite3                    ← auto-created after migrate
│
├── phishing_detector/            ← Django project config
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
│
├── detector/                     ← Main app
│   ├── models.py                 ← URLScan database model
│   ├── views.py                  ← Scan, result, history, API
│   ├── forms.py                  ← URL input form
│   ├── urls.py                   ← URL routing
│   ├── admin.py                  ← Django admin config
│   ├── feature_extractor.py      ← 12 URL features
│   └── ml_model.py               ← Model loader + predict()
│
├── accounts/                     ← Auth app
│   ├── views.py                  ← login / register / logout
│   ├── forms.py                  ← Auth forms
│   └── urls.py
│
├── ml/
│   ├── train_model.py            ← Dataset + training script
│   └── phishing_model.pkl        ← Saved trained model
│
├── templates/
│   ├── base.html                 ← Dark theme base layout
│   ├── detector/
│   │   ├── index.html            ← Dashboard + scan form
│   │   ├── result.html           ← Prediction result
│   │   └── history.html          ← Paginated scan log
│   └── accounts/
│       ├── login.html
│       └── register.html
│
└── static/                       ← CSS / JS / images
```

---

## ⚡ Quick Setup (5 minutes)

### 1. Clone / download the project
```bash
git clone <repo-url>
cd phishing_detector
```

### 2. Create and activate a virtual environment
```bash
python -m venv venv

# macOS / Linux
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Train the ML model *(only needed once)*
```bash
python ml/train_model.py
```
This generates `ml/phishing_model.pkl`.

### 5. Apply database migrations
```bash
python manage.py migrate
```

### 6. Create an admin superuser
```bash
python manage.py createsuperuser
```

### 7. Run the development server
```bash
python manage.py runserver
```

Open **http://127.0.0.1:8000** in your browser.

---

## 🗺️ Pages & Routes

| URL | Description |
|-----|-------------|
| `/` | Dashboard — URL scan form + stats |
| `/result/<id>/` | Prediction result + feature breakdown |
| `/history/` | Paginated scan history with filters |
| `/accounts/login/` | Login page |
| `/accounts/register/` | Sign-up page |
| `/accounts/logout/` | Logout |
| `/admin/` | Django admin (superuser only) |
| `/api/predict/` | REST API endpoint (POST) |

---

## 🤖 ML Model Details

| Property | Value |
|----------|-------|
| Algorithm | Random Forest (200 trees) |
| Features | 12 URL-derived numeric features |
| Training samples | 500 (balanced: 250 phishing / 250 legitimate) |
| Scaling | StandardScaler (in Pipeline) |
| Test accuracy | ~100% on synthetic data |

### 12 Extracted Features

1. **url_length** — total character count
2. **hostname_length** — length of the domain
3. **ip_in_url** — IPv4 address in hostname (0/1)
4. **uses_https** — scheme is HTTPS (0/1)
5. **dot_count** — number of `.` characters
6. **hyphen_count** — number of `-` characters
7. **at_symbol_count** — number of `@` symbols
8. **subdomain_count** — depth of subdomain nesting
9. **suspicious_count** — count of 24 known phishing keywords
10. **path_depth** — number of `/` slashes in path
11. **has_query** — URL contains a query string (0/1)
12. **has_double_slash** — `//` present in URL path (0/1)

---

## 🔌 REST API

**Endpoint:** `POST /api/predict/`

**Request:**
```bash
curl -X POST http://127.0.0.1:8000/api/predict/ \
     -H "Content-Type: application/json" \
     -d '{"url": "http://paypal-login-secure.verify.tk/signin"}'
```

**Response:**
```json
{
  "url": "http://paypal-login-secure.verify.tk/signin",
  "label": "Phishing",
  "is_phishing": true,
  "confidence": 97.5,
  "features": {
    "url_length": 48,
    "hostname_length": 35,
    "ip_in_url": 0,
    "uses_https": 0,
    "dot_count": 3,
    "hyphen_count": 2,
    "at_symbol_count": 0,
    "subdomain_count": 2,
    "suspicious_count": 3,
    "path_depth": 1,
    "has_query": 0,
    "has_double_slash": 0
  }
}
```

---

## 🔐 Default Demo Credentials

After running migrations and `createsuperuser`, you can also log in with:

| Username | Password |
|----------|----------|
| admin | *(your chosen password)* |

---

## 🚀 Production Checklist

- [ ] Set `DEBUG = False` in `settings.py`
- [ ] Set `SECRET_KEY` via environment variable
- [ ] Add your domain to `ALLOWED_HOSTS`
- [ ] Run `python manage.py collectstatic`
- [ ] Use PostgreSQL instead of SQLite
- [ ] Serve with Gunicorn + Nginx
- [ ] Set up HTTPS with Let's Encrypt

---

## 📦 Dependencies

```
Django>=4.2
scikit-learn>=1.3.0
numpy>=1.24.0
pandas>=2.0.0
joblib>=1.3.0
```
