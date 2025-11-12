import os
import io
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, UploadFile, File as FastFile, Form, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from database import db, create_document, get_documents
from schemas import User, Magiclinktoken, File as FileDoc, Chatmessage

from pdfminer.high_level import extract_text
from cryptography.fernet import Fernet
import jwt
import requests
from bson import ObjectId

APP_NAME = "Finanalyzer"

DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
DEEPSEEK_API_BASE = os.getenv("DEEPSEEK_API_BASE", "https://api.deepseek.com/v1")

FILE_ENC_KEY = os.getenv("FILE_ENC_KEY") or Fernet.generate_key().decode()
fernet = Fernet(FILE_ENC_KEY.encode())

JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
JWT_ALGO = "HS256"

LOCAL_STORAGE_DIR = os.getenv("LOCAL_STORAGE_DIR", "files")
os.makedirs(LOCAL_STORAGE_DIR, exist_ok=True)

app = FastAPI(title=APP_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class MagicLinkRequest(BaseModel):
    email: str

class ChatRequest(BaseModel):
    file_id: str
    message: str

class ExportRequest(BaseModel):
    export_type: str = "all"

# Helpers

def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    return db["user"].find_one({"email": email}) if db is not None else None


def ensure_user(email: str) -> str:
    u = get_user_by_email(email)
    if u:
        return str(u["_id"])
    user_id = create_document("user", User(email=email))
    return user_id


def decode_auth(request: Request) -> Dict[str, Any]:
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = auth.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


# Auth endpoints
@app.post("/auth/magiclink")
def send_magic_link(req: MagicLinkRequest):
    email = req.email.lower().strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email")
    ensure_user(email)
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(minutes=15)
    create_document("magiclinktoken", Magiclinktoken(email=email, token=token, expires_at=expires))
    return {"login_token": token, "note": "Email simulated. POST /auth/verify with email and token to get JWT."}


@app.post("/auth/verify")
def verify_magic_link(email: str = Form(...), token: str = Form(...)):
    rec = db["magiclinktoken"].find_one({"email": email, "token": token, "used": False})
    if not rec:
        raise HTTPException(status_code=400, detail="Invalid token")
    if rec.get("expires_at") and datetime.now(timezone.utc) > rec["expires_at"]:
        raise HTTPException(status_code=400, detail="Token expired")
    db["magiclinktoken"].update_one({"_id": rec["_id"]}, {"$set": {"used": True}})
    user_id = ensure_user(email)
    jwt_token = jwt.encode({"sub": user_id, "email": email, "exp": datetime.utcnow() + timedelta(days=7)}, JWT_SECRET, algorithm=JWT_ALGO)
    return {"access_token": jwt_token}


# Upload & files
@app.post("/files/upload")
def upload_pdf(request: Request, pdf: UploadFile = FastFile(...)):
    payload = decode_auth(request)
    user_id = payload.get("sub")

    if pdf.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Only PDF allowed")

    contents = pdf.file.read()
    if len(contents) > 50 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Max 50MB")

    # Simple rate limit for free plan: 10 PDFs/hour
    user = db["user"].find_one({"_id": ObjectId(user_id)})
    plan = (user or {}).get("plan", "free")
    if plan == "free":
        window_start = datetime.now(timezone.utc) - timedelta(hours=1)
        count = db["file"].count_documents({"user_id": user_id, "upload_date": {"$gte": window_start}})
        if count >= 10:
            raise HTTPException(status_code=429, detail="Rate limit exceeded: 10 PDFs/hour on free plan")

    enc = fernet.encrypt(contents)
    storage_path = os.path.join(LOCAL_STORAGE_DIR, f"{secrets.token_hex(16)}.pdf.enc")
    with open(storage_path, "wb") as f:
        f.write(enc)

    file_id = create_document("file", FileDoc(
        user_id=user_id,
        filename=pdf.filename,
        size_bytes=len(contents),
        storage_path=storage_path,
        upload_date=datetime.now(timezone.utc),
    ))

    # Extract text and analyze
    try:
        text = extract_text(io.BytesIO(contents))
    except Exception:
        text = ""

    doc_type = detect_document_type(text)
    fiscal_year = detect_fiscal_year(text)
    analysis = generate_analysis(text)

    db["file"].update_one({"_id": ObjectId(file_id)}, {"$set": {
        "status": "complete",
        "doc_type": doc_type,
        "fiscal_year": fiscal_year,
        "analysis": analysis,
        "updated_at": datetime.now(timezone.utc)
    }})

    return {"file_id": file_id, "status": "complete"}


@app.get("/files")
def list_files(request: Request):
    payload = decode_auth(request)
    user_id = payload.get("sub")
    docs = get_documents("file", {"user_id": user_id})
    out = []
    for d in docs:
        d["_id"] = str(d["_id"])
        out.append(d)
    return {"files": out}


@app.post("/chat")
def chat(req: ChatRequest, request: Request):
    payload = decode_auth(request)
    user_id = payload.get("sub")

    try:
        file_doc = db["file"].find_one({"_id": ObjectId(req.file_id), "user_id": user_id})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid file id")

    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    context = file_doc.get("analysis", {})
    answer = deepseek_chat(req.message, context)

    create_document("chatmessage", Chatmessage(user_id=user_id, file_id=req.file_id, role="user", content=req.message))
    create_document("chatmessage", Chatmessage(user_id=user_id, file_id=req.file_id, role="assistant", content=answer))

    db["file"].update_one({"_id": file_doc["_id"]}, {"$set": {"last_queried": datetime.now(timezone.utc)}})

    return {"answer": answer}


@app.post("/export")
def export_data(request: Request, body: ExportRequest):
    payload = decode_auth(request)
    user_id = payload.get("sub")

    files = get_documents("file", {"user_id": user_id})
    chats = get_documents("chatmessage", {"user_id": user_id})

    for f in files:
        f["_id"] = str(f["_id"])
    for c in chats:
        c["_id"] = str(c["_id"])

    data = {"files": files, "chats": chats}
    return JSONResponse(content=data)


@app.delete("/gdpr/delete")
def gdpr_delete(request: Request):
    payload = decode_auth(request)
    user_id = payload.get("sub")
    db["chatmessage"].delete_many({"user_id": user_id})
    files = list(db["file"].find({"user_id": user_id}))
    for f in files:
        try:
            path = f.get("storage_path")
            if path and os.path.exists(path):
                os.remove(path)
        except Exception:
            pass
    db["file"].delete_many({"user_id": user_id})
    db["user"].delete_one({"_id": ObjectId(user_id)})
    return {"status": "deleted"}


@app.get("/")
def read_root():
    return {"message": f"{APP_NAME} backend running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


# Utilities

def detect_document_type(text: str) -> Optional[str]:
    text_lower = text.lower()
    if any(k in text_lower for k in ["balance sheet", "assets", "liabilities", "equity"]):
        return "balance_sheet"
    if any(k in text_lower for k in ["income statement", "profit and loss", "revenue", "expenses"]):
        return "pnl"
    if any(k in text_lower for k in ["cash flow", "operating activities", "investing activities", "financing activities"]):
        return "cash_flow"
    return None


def detect_fiscal_year(text: str) -> Optional[str]:
    import re
    m = re.search(r"fiscal year\s*(\d{4})", text.lower())
    if m:
        return m.group(1)
    m2 = re.search(r"for the year ended\s*([a-zA-Z]+\s+\d{1,2},\s*\d{4})", text, re.IGNORECASE)
    if m2:
        return m2.group(1)
    return None


def generate_analysis(text: str) -> Dict[str, Any]:
    prompt = {
        "instruction": "Analyze financial statements and return JSON with fields: health_score (0-100), trends (summary), scenarios (1yr,5yr optimistic/realistic/conservative), recommendations (3-5 items), risks (list). Keep it concise.",
        "context": text[:15000]
    }

    if DEEPSEEK_API_KEY:
        try:
            headers = {"Authorization": f"Bearer {DEEPSEEK_API_KEY}", "Content-Type": "application/json"}
            resp = requests.post(f"{DEEPSEEK_API_BASE}/chat/completions", json={
                "model": "deepseek-chat",
                "messages": [
                    {"role": "system", "content": "You are a financial analysis engine. Return valid JSON only."},
                    {"role": "user", "content": str(prompt)}
                ],
                "temperature": 0.2
            }, headers=headers, timeout=30)
            data = resp.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "{}")
            import json
            return json.loads(content)
        except Exception:
            pass
    return {
        "health_score": 65,
        "trends": {"revenue": "stable", "costs": "slightly increasing"},
        "scenarios": {
            "1yr": {"optimistic": "+12%", "realistic": "+5%", "conservative": "+1%"},
            "5yr": {"optimistic": "+70%", "realistic": "+35%", "conservative": "+10%"}
        },
        "recommendations": [
            "Improve gross margin by renegotiating supplier terms",
            "Reduce OPEX by 5% via process automation",
            "Expand into two high-ROI channels",
            "Increase cash reserves to 6 months runway"
        ],
        "risks": ["Customer concentration", "Debt servicing costs", "FX volatility"]
    }


def deepseek_chat(message: str, context: Dict[str, Any]) -> str:
    if DEEPSEEK_API_KEY:
        try:
            headers = {"Authorization": f"Bearer {DEEPSEEK_API_KEY}", "Content-Type": "application/json"}
            user_msg = f"Context: {context}\n\nQuestion: {message}. Keep answer concise."
            resp = requests.post(f"{DEEPSEEK_API_BASE}/chat/completions", json={
                "model": "deepseek-chat",
                "messages": [
                    {"role": "system", "content": "You are a financial analysis assistant."},
                    {"role": "user", "content": user_msg}
                ],
                "temperature": 0.2
            }, headers=headers, timeout=30)
            data = resp.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            return content
        except Exception:
            return "Unable to reach analysis engine right now."
    return "This is a placeholder answer based on the available analysis summary."


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
