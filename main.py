from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import santa
from pathlib import Path

app = FastAPI(title="Secret Santa API")

# --------------------------
# Request models
# --------------------------

class RegisterRequest(BaseModel):
  name: str
  password: str

class DecryptRequest(BaseModel):
  password: str
  ciphertext_b64: str


# --------------------------
# Endpoints
# --------------------------

@app.post("/register")
async def register_user(req: RegisterRequest):
  try:
    santa.register(req.name, req.password)
    return {"status": "ok", "message": f"{req.name} registered"}
  except Exception as e:
    raise HTTPException(status_code=400, detail=str(e))


@app.post("/assign")
async def generate_assign():
  try:
    santa.generate_assignments()
    return {"status": "ok", "message": "Assignments generated"}
  except Exception as e:
    raise HTTPException(status_code=500, detail=str(e))


@app.post("/decrypt")
async def decrypt_assignment(req: DecryptRequest):
  try:
    result = santa.decrypt_with_password(req.password, req.ciphertext_b64)
    return {"status": "ok", "receiver": result}
  except Exception as e:
    raise HTTPException(status_code=400, detail=str(e))


@app.get("/registry")
async def get_registry():
  try:
    return santa.load_registry()
  except Exception as e:
    raise HTTPException(status_code=500, detail=str(e))


@app.get("/assignments")
async def get_assignments():
  try:
    return santa.load_assignments()
  except Exception as e:
    raise HTTPException(status_code=500, detail=str(e))


html = Path('ui.html').read_text()

@app.get('/')
async def root():
  return HTMLResponse(html)

