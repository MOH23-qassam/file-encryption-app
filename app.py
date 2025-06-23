
from fastapi import FastAPI, File, UploadFile, Form, Request
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import shutil
import uvicorn

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data: bytes, password: str, original_ext: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ext_bytes = original_ext.encode().ljust(16, b' ')
    encrypted = aesgcm.encrypt(nonce, ext_bytes + data, None)
    return salt + nonce + encrypted

def decrypt_data(encrypted_data: bytes, password: str):
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    cipher_text = encrypted_data[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    decrypted = aesgcm.decrypt(nonce, cipher_text, None)
    original_ext = decrypted[:16].decode().strip()
    return decrypted[16:], original_ext

@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    if username == "كتائب القسام" and password == "7اكتوبر2023":
        return RedirectResponse("/encryptor", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": "بيانات الدخول غير صحيحة"})

@app.get("/encryptor", response_class=HTMLResponse)
async def main_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/encrypt")
async def encrypt(file: UploadFile = File(...), password: str = Form(...)):
    contents = await file.read()
    _, ext = os.path.splitext(file.filename)
    encrypted = encrypt_data(contents, password, ext)
    out_path = f"static/temp/{file.filename}.enc"
    with open(out_path, "wb") as f:
        f.write(encrypted)
    return FileResponse(out_path, filename=file.filename + ".enc", media_type='application/octet-stream')

@app.post("/decrypt")
async def decrypt(file: UploadFile = File(...), password: str = Form(...)):
    contents = await file.read()
    try:
        decrypted_data, ext = decrypt_data(contents, password)
        base_name = os.path.splitext(file.filename)[0].replace(".enc", "")
        output_path = f"static/temp/{base_name}_restored{ext}"
        with open(output_path, "wb") as f:
            f.write(decrypted_data)
        return FileResponse(output_path, filename=os.path.basename(output_path), media_type='application/octet-stream')
    except Exception:
        return HTMLResponse("❌ كلمة المرور غير صحيحة أو الملف تالف.", status_code=400)

os.makedirs("static/temp", exist_ok=True)
