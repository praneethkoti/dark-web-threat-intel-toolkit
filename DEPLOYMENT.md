# Deploying to Streamlit Community Cloud

Five steps from a fresh GitHub push to a live public URL.

---

## Prerequisites

- GitHub repo is public (or you have a Streamlit Cloud Team/Pro plan for private repos)
- `data/dashboard_demo.db` is committed — it ships the pre-populated demo database
- `requirements.txt` in the repo root is the cloud-safe dependency list (excludes torch/transformers/spacy/selenium)
- Full dev dependencies are in `requirements-dev.txt` for local development and CI

---

## Deployment Steps

### 1. Sign in to Streamlit Cloud

Go to **[share.streamlit.io](https://share.streamlit.io)** and sign in with GitHub.

### 2. Create a new app

Click **"New app"** in the top-right corner.

### 3. Select the repository

| Field | Value |
|---|---|
| Repository | `praneethkoti/dark-web-threat-intel-toolkit` |
| Branch | `main` |
| Main file path | `dashboard/app.py` |

Streamlit Cloud automatically reads `requirements.txt` from the repo root — no custom path needed.

### 4. Add secrets (optional — enables AI Summarizer)

In **Advanced settings → Secrets**, paste:

```toml
OPENAI_API_KEY = "sk-..."
ANTHROPIC_API_KEY = "sk-ant-..."
```

Without these the AI Summarizer page still loads and shows a helpful info card explaining how to configure each backend. All other pages work without any secrets.

### 5. Deploy

Click **"Deploy"**. Streamlit Cloud will install `requirements.txt`, run `dashboard/app.py`, and give you a public URL within ~2 minutes.

Update the `<DEPLOYMENT_URL_TBD>` placeholder in `README.md` with the URL once it is live.

---

## Local Development

Install the full dependency set (includes torch, spacy, selenium, etc.):

```bash
pip install -r requirements-dev.txt
python -m spacy download en_core_web_sm
```

---

## Troubleshooting

### App crashes immediately on boot

**Most likely cause:** a package in `requirements.txt` failed to install or a required import is missing.

Check: **App menu (⋮) → Logs** in the Streamlit Cloud UI. Look for `ModuleNotFoundError` or `pip install` failures.

**Fix:** verify `requirements.txt` includes the failing package. Do not add `torch` or `transformers` — they will exceed the 1 GB free-tier RAM limit and cause the app to crash.

### "No data in the database"

**Cause:** `data/dashboard_demo.db` is not committed or is being ignored by `.gitignore`.

**Fix:** confirm `.gitignore` contains the exception line:
```
!data/dashboard_demo.db
```
Then run `git add data/dashboard_demo.db` and push.

### AI Summarizer shows "No AI backends available"

**Cause:** API keys are not configured as Streamlit secrets.

**Fix:** In **Advanced settings → Secrets**, add `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` (see Step 4 above). Then click **Reboot app**.

### Memory limit exceeded (app OOMs)

**Cause:** a heavy package (torch, transformers, spacy, selenium) crept into `requirements.txt`.

**Fix:** remove it. These packages are only needed for local fine-tuning and headless scraping — neither is required for the dashboard. They belong in `requirements-dev.txt` only.

### Wrong Python version

Streamlit Cloud defaults to Python 3.11. The app is tested on 3.11 and 3.13. If you need a specific version, add a `.python-version` file to the repo root containing just the version string (e.g. `3.11`).

---

## Keeping the Demo DB Up to Date

The committed `data/dashboard_demo.db` is a snapshot. To refresh it:

```bash
# Run the full pipeline locally to regenerate the DB
python demo.py --no-dashboard

# Copy the updated DB to the committed path
copy data\threat_intel.db data\dashboard_demo.db

# Commit and push
git add data/dashboard_demo.db
git commit -m "chore: refresh demo database snapshot"
git push
```

Streamlit Cloud redeploys automatically on push.
