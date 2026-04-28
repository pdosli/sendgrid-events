import base64
import hmac
import hashlib
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import os

app = FastAPI()

SENDGRID_PUBLIC_KEY = os.getenv("SENDGRID_PUBLIC_KEY")


# SENDGRID SIGNATURE VERIFICATION
def verify_sendgrid_signature(request: Request, body: bytes):
    signature = request.headers.get("x-twilio-email-event-webhook-signature")
    timestamp = request.headers.get("x-twilio-email-event-webhook-timestamp")

    if not signature or not timestamp:
        raise HTTPException(status_code=400, detail="Missing SendGrid signature headers")

    # Build the signed payload
    signed_payload = timestamp.encode() + body

    # Verify using HMAC SHA256 with the SendGrid public key
    try:
        public_key_bytes = base64.b64decode(SENDGRID_PUBLIC_KEY)
    except Exception:
        raise HTTPException(status_code=500, detail="Invalid SendGrid public key")

    verifier = hmac.new(public_key_bytes, signed_payload, hashlib.sha256)
    expected_signature = base64.b64encode(verifier.digest()).decode()

    if not hmac.compare_digest(expected_signature, signature):
        raise HTTPException(status_code=401, detail="Invalid SendGrid signature")


@app.post("/sendgrid/events")
async def sendgrid_events(request: Request):
    raw_body = await request.body()
    verify_sendgrid_signature(request, raw_body)
    events = await request.json()
    print("Received events:", events)
    return JSONResponse({"status": "ok"})
    