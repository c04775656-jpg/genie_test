import os
import sqlite3
import hashlib
import jwt
import datetime
import time
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.environ.get("JWT_SECRET", "change-this-secret")
DATABRICKS_HOST = os.environ.get("DATABRICKS_HOST")
DATABRICKS_TOKEN = os.environ.get("DATABRICKS_TOKEN")
GENIE_SPACE_ID = os.environ.get("GENIE_SPACE_ID")

DB_PATH = "users.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password_hash TEXT)''')
    conn.commit()
    conn.close()

init_db()

class LoginRequest(BaseModel):
    username: str
    password: str

class ChatRequest(BaseModel):
    message: str
    conversation_id: str = None

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_token(authorization: str):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="缺少 token")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["username"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token 已過期")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token 無效")

@app.post("/register")
def register(req: LoginRequest):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (req.username,))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="使用者已存在")
    c.execute("INSERT INTO users VALUES (?, ?)", (req.username, hash_password(req.password)))
    conn.commit()
    conn.close()
    return {"message": "使用者建立成功"}

@app.post("/login")
def login(req: LoginRequest):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username = ?", (req.username,))
    row = c.fetchone()
    conn.close()
    if not row or row[0] != hash_password(req.password):
        raise HTTPException(status_code=401, detail="帳號或密碼錯誤")
    token = jwt.encode({
        "username": req.username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, SECRET_KEY, algorithm="HS256")
    return {"token": token}

@app.post("/chat")
def chat(req: ChatRequest, authorization: str = Header(None)):
    username = verify_token(authorization)

    headers = {
        "Authorization": f"Bearer {DATABRICKS_TOKEN}",
        "Content-Type": "application/json"
    }

    if req.conversation_id:
        # 在現有會話中繼續對話
        url = f"{DATABRICKS_HOST}/api/2.0/genie/spaces/{GENIE_SPACE_ID}/conversations/{req.conversation_id}/messages"
        payload = {"content": req.message}
    else:
        # 開始新的會話
        url = f"{DATABRICKS_HOST}/api/2.0/genie/spaces/{GENIE_SPACE_ID}/start-conversation"
        payload = {"content": req.message}

    response = requests.post(url, headers=headers, json=payload)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)

    data = response.json()
    conv_id = data["conversation_id"]
    msg_id = data["message_id"]

    # 輪詢直到訊息處理完成
    poll_url = f"{DATABRICKS_HOST}/api/2.0/genie/spaces/{GENIE_SPACE_ID}/conversations/{conv_id}/messages/{msg_id}"
    for _ in range(60):  # 最多輪詢 60 次
        poll_resp = requests.get(poll_url, headers=headers)
        if poll_resp.status_code != 200:
            break

        msg_data = poll_resp.json()
        status = msg_data.get("status")

        if status == "COMPLETED":
            return {
                "conversation_id": conv_id,
                "message_id": msg_id,
                "status": status,
                "answer": msg_data.get("attachments", [])
            }
        elif status in ("FAILED", "CANCELLED"):
            raise HTTPException(status_code=500, detail=f"Genie 處理失敗：{status}")

        time.sleep(2)  # 每 2 秒輪詢一次

    raise HTTPException(status_code=504, detail="Genie 處理逾時")

@app.get("/")
def root():
    return {"status": "ok", "message": "Databricks Genie 聊天後端正在運行"}
