import base64, os
from functools import lru_cache
import httpx
from Crypto.Cipher import AES
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from app.tokenizer import tokenize_value

app = FastAPI(title="Secure Vault Tokenizer", version="2.0.0")
class TokenizeRequest(BaseModel): type: str; value: str
class EncryptRequest(BaseModel): value: str; dek: str; format_type: str
class DecryptRequest(BaseModel): payload: str; dek: str; format_type: str

@lru_cache
def fpe_key():
    token = os.getenv("VAULT_TOKEN")
    if not token: raise RuntimeError("VAULT_TOKEN is required")
    response = httpx.get(f"{os.getenv('VAULT_URL', 'http://127.0.0.1:8200').rstrip('/')}/v1/secret/data/tokenizer", headers={"X-Vault-Token": token}, timeout=5)
    response.raise_for_status(); return response.json()["data"]["data"]["fpe_key"]

@app.get("/health")
def health(): return {"status": "ok", "service": "tokenizer"}
@app.post("/tokenize")
def tokenize(payload: TokenizeRequest):
    try: return {"token": tokenize_value(payload.value, payload.type, fpe_key()), "format_type": payload.type}
    except (ValueError, KeyError, httpx.HTTPError) as exc: raise HTTPException(400, str(exc)) from exc
@app.post("/encrypt")
def encrypt(payload: EncryptRequest):
    key = base64.b64decode(payload.dek)
    if len(key) != 32: raise HTTPException(400, "AES-256-GCM requires a 256-bit data key")
    cipher = AES.new(key, AES.MODE_GCM); cipher.update(payload.format_type.encode()); ciphertext, tag = cipher.encrypt_and_digest(payload.value.encode())
    return {"payload": ".".join(base64.b64encode(value).decode() for value in (cipher.nonce, tag, ciphertext))}
@app.post("/decrypt")
def decrypt(payload: DecryptRequest):
    try:
        nonce, tag, ciphertext = (base64.b64decode(value) for value in payload.payload.split(".")); cipher = AES.new(base64.b64decode(payload.dek), AES.MODE_GCM, nonce=nonce); cipher.update(payload.format_type.encode())
        return {"value": cipher.decrypt_and_verify(ciphertext, tag).decode()}
    except (ValueError, UnicodeDecodeError) as exc: raise HTTPException(400, "Invalid encrypted payload") from exc
