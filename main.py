import base64
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import os
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

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

    # Decode the public key
    try:
        public_key = VerifyKey(base64.b64decode(SENDGRID_PUBLIC_KEY))
    except Exception:
        raise HTTPException(status_code=500, detail="Invalid SendGrid public key")

    # Verify signature
    try:
        public_key.verify(signed_payload, base64.b64decode(signature))
    except BadSignatureError:
        raise HTTPException(status_code=401, detail="Invalid SendGrid signature")


@app.post("/sendgrid/events")
async def sendgrid_events(request: Request):
    raw_body = await request.body()
    verify_sendgrid_signature(request, raw_body)
    events = await request.json()
    print("Received events:", events)
    return JSONResponse({"status": "ok"})
    