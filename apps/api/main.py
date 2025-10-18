from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pathlib import Path

from modules.scan_phishing.service import router as phishing_router
from modules.scan_malware.service import router as malware_router
from modules.pcap.service import router as pcap_router

app = FastAPI(title="Defense Capstone API", version="0.1.0")
app.include_router(phishing_router)
app.include_router(malware_router)
app.include_router(pcap_router)

# Absolute path to project-root/public
STATIC_DIR = Path(__file__).resolve().parents[2] / "public"
assert STATIC_DIR.exists(), f"Static dir not found: {STATIC_DIR}"

# Serve the site at /app to avoid any conflicts
app.mount("/app", StaticFiles(directory=str(STATIC_DIR), html=True), name="app")

# Redirect / -> /app/index.html
@app.get("/", include_in_schema=False)
def home():
    return RedirectResponse(url="/app/index.html")
