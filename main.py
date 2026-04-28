import base64
import json
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
import os

app = FastAPI()

SENDGRID_PUBLIC_KEY = os.getenv("SENDGRID_PUBLIC_KEY")


# SENDGRID SIGNATURE VERIFICATION
def verify_sendgrid_signature(request: Request, body: bytes):
    signature_b64 = request.headers.get("X-Twilio-Email-Event-Webhook-Signature")
    timestamp = request.headers.get("X-Twilio-Email-Event-Webhook-Timestamp")

    if not signature or not timestamp:
        raise HTTPException(status_code=400, detail="Missing SendGrid signature headers")

    # Decode signature (ASN.1 DER-encoded ECDSA signature)
    signature = base64.b64decode(signature_b64)

    # Load ECDSA public key
    try:
        public_key = serialization.load_pem_public_key(
            SENDGRID_PUBLIC_KEY.encode("utf-8")
        )
    except Exception:
        raise HTTPException(status_code=500, detail="Invalid SendGrid public key")

    # Hash timestamp + body using SHA256
    digest = hashes.Hash(hashes.SHA256())
    digest.update(timestamp.encode())
    digest.update(body)
    hashed_payload = digest.finalize()

    # Verify ECDSA signature
    try:
        public_key.verify(signature, hashed_payload, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise HTTPException(status_code=401, detail="Invalid SendGrid signature")


@app.post("/sendgrid/events")
async def sendgrid_events(request: Request):
    raw_body = await request.body()
    verify_sendgrid_signature(request, raw_body)
    events = await request.json()
    print("Received events:", events)
    return JSONResponse({"status": "ok"})
    