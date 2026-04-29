import base64
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import os

app = FastAPI()

WEBHOOK_USER = os.getenv("WEBHOOK_USER")
WEBHOOK_PASS = os.getenv("WEBHOOK_PASS")


def verify_basic_auth(request: Request):
    auth = request.headers.get("authorization")

    if not auth or not auth.startswith("Basic "):
        raise HTTPException(status_code=401, detail="Authentication required")

    encoded = auth.split(" ")[1]

    try:
        decoded = base64.b64decode(encoded).decode()
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid auth header")

    username, password = decoded.split(":", 1)

    if username != WEBHOOK_USER or password != WEBHOOK_PASS:
        raise HTTPException(status_code=403, detail="Forbidden")


@app.post("/sendgrid/events")
async def sendgrid_events(request: Request):
    verify_basic_auth(request)
    events = await request.json()
    print("Received events:", events)
    return JSONResponse({"status": "ok"})
    