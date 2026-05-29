# This file contains FAKE/EXAMPLE credentials for testing cyberscanner's secret detection.
# These are not real secrets — they follow the format but are not valid.

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLEKEY"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"

STRIPE_SECRET = "sk_live_51H7ExampleKeyTestValue12345"

OPENAI_KEY = "sk-" + "a" * 48  # won't match — split across expression

DB_URL = "postgresql://admin:s3cr3tpassword@db.example.com/mydb"

# This should NOT be flagged (too short / not real format)
api_key = "short"
