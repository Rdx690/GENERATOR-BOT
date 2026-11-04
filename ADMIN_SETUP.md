# Admin dashboard setup

This is a separate, safe admin-only dashboard for manually recording daily like counts by player UID. It supports the India (IND) region only. It does **not** automate likes or call any game endpoints.

## Run locally

```bash
pip install -r requirements.txt
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('YOUR_NEW_ADMIN_PASSWORD'))"
```

Set these environment variables on your hosting provider (never commit their values):

- `ADMIN_PASSWORD_HASH`: output from the command above
- `FLASK_SECRET_KEY`: a long random secret
- `LIKES_DB_PATH`: optional persistent SQLite file path (default: `daily_likes.sqlite3`)

Then run:

```bash
gunicorn admin_dashboard:app
```

The hosting platform must provide persistent disk storage for SQLite data to survive restarts/redeployments. Use HTTPS in production. Keep the password hash and Flask secret in hosting environment variables, not in HTML or GitHub.
