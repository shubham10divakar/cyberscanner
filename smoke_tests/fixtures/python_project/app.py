"""Sample app — deliberately contains fake secrets for smoke testing secret detection."""

import os

# Fake AWS key (format-correct but not real)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLEKEY"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Fake GitHub token
GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"

# Fake DB URL with credentials
DATABASE_URL = "postgresql://admin:supersecret123@db.prod.example.com/myapp"

# Fake Stripe key
STRIPE_SECRET_KEY = "sk_live_51H7TestExampleKeyValue12345678"


def get_data():
    return {"status": "ok"}
