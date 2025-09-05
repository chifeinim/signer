import os
from typing import List
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import httpx

APP_API_KEY   = os.environ["SIGNER_API_KEY"]
SUPABASE_URL  = os.environ["SUPABASE_URL"]            # e.g. https://zfoqolfmrwsohdxuqmba.supabase.co
SERVICE_KEY   = os.environ["SUPABASE_SERVICE_KEY"]    # service role key (kept ONLY on Railway)
ALLOWED_BUCKET = os.environ.get("ALLOWED_BUCKET", "anda-media")
ALLOWED_PREFIXES: List[str] = [
    p.strip() for p in os.environ.get("ALLOWED_PREFIXES", "attachments/").split(",") if p.strip()
]

app = FastAPI()

class SignRequest(BaseModel):
    bucket: str
    object: str         # path inside bucket, e.g. "attachments/video/file.mp4"
    expiresIn: int = 600

class SignResponse(BaseModel):
    url: str

def _is_allowed(bucket: str, obj: str) -> bool:
    if bucket != ALLOWED_BUCKET:
        return False
    return any(obj.startswith(pref) for pref in ALLOWED_PREFIXES)

@app.post("/sign", response_model=SignResponse)
async def sign(req: SignRequest, x_api_key: str = Header(None)):
    if x_api_key != APP_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not _is_allowed(req.bucket, req.object):
        raise HTTPException(status_code=403, detail="Path not allowed")

    endpoint = f"{SUPABASE_URL}/storage/v1/object/sign/{req.bucket}/{req.object}"
    headers = {"Authorization": f"Bearer {SERVICE_KEY}", "apikey": SERVICE_KEY}
    async with httpx.AsyncClient(timeout=8) as client:
        r = await client.post(endpoint, json={"expiresIn": req.expiresIn}, headers=headers)
    if r.status_code >= 300:
        raise HTTPException(status_code=502, detail=f"Supabase error: {r.text}")
    signed_path = r.json().get("signedURL")
    if not signed_path:
        raise HTTPException(status_code=502, detail="No signedURL returned")
    return SignResponse(url=f"{SUPABASE_URL}{signed_path}")

@app.get("/healthz")
async def healthz():
    return {"ok": True}
