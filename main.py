from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

@app.post("/sendgrid/events")
async def sendgrid_events(request: Request):
    events = await request.json()
    # Process events (store in DB, log, etc.)
    print("Received events:", events)
    return JSONResponse({"status": "ok"})
