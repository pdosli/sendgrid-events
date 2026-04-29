import base64
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key

app = FastAPI()

WEBHOOK_USER = os.getenv("WEBHOOK_USER")
WEBHOOK_PASS = os.getenv("WEBHOOK_PASS")
SENDGRID_PUBLIC_KEY = os.getenv("SENDGRID_PUBLIC_KEY")


def convert_public_key_to_ecdsa(public_key: str):
        """
        Convert the public key string to an EllipticCurvePublicKey object.

        :param public_key: verification key under Mail Settings
        :type public_key string
        :return: An EllipticCurvePublicKey object using the ECDSA algorithm
        :rtype cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey
        """
        pem_key = "-----BEGIN PUBLIC KEY-----\n" + public_key + "\n-----END PUBLIC KEY-----"
        return load_pem_public_key(pem_key.encode("utf-8"))


def verify_signature(payload: str, signature: str, timestamp: str, public_key: str):
        """
        Verify signed event webhook requests.

        :param payload: event payload in the request body
        :type payload: string
        :param signature: value obtained from the 'X-Twilio-Email-Event-Webhook-Signature' header
        :type signature: string
        :param timestamp: value obtained from the 'X-Twilio-Email-Event-Webhook-Timestamp' header
        :type timestamp: string
        :param public_key: elliptic curve public key
        :type public_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey
        :return: true or false if signature is valid
        """
        timestamped_payload = (timestamp + payload).encode('utf-8')
        decoded_signature = base64.b64decode(signature)

        key = convert_public_key_to_ecdsa(public_key)
        try:
            key.verify(decoded_signature, timestamped_payload, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False


def verify_basic_auth(request: Request):
    auth = request.headers.get("authorization")

    if not auth or not auth.startswith("Basic "):
        raise HTTPException(status_code=401, detail="Missing authorization header")

    encoded = auth.split(" ")[1]
    decoded = base64.b64decode(encoded).decode()
    username, password = decoded.split(":", 1)

    if username != WEBHOOK_USER or password != WEBHOOK_PASS:
        raise HTTPException(status_code=403, detail="Invalid authorization")


@app.post("/sendgrid/events")
async def sendgrid_events(request: Request):
    signature = request.headers.get("X-Twilio-Email-Event-Webhook-Signature")
    timestamp = request.headers.get("X-Twilio-Email-Event-Webhook-Timestamp")
    
    if not signature or not timestamp:
        raise HTTPException(status_code=401, detail="Missing SendGrid signature headers")
        
    payload = await request.body()
    verified = verify_signature(
        payload,
        signature,
        timestamp,
        public_key=SENDGRID_PUBLIC_KEY
    )
    
    if not verified:
        raise HTTPException(status_code=403, detail="Invalid SendGrid signature")
    
    verify_basic_auth(request)
    events = await request.json()
    print("Received events:", events)
    return JSONResponse({"status": "ok"})
