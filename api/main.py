from fastapi import FastAPI, Form, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from datetime import datetime, timedelta

# App setup
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dummy user (replace with DB check in real app)
dummy_user = {
    "aadhaar": "111111111111",
    "mobile": "9876543210",
    "otp": "123456"
}

# JWT config
SECRET_KEY = "your-super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        aadhaar = payload.get("sub")
        if aadhaar is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return aadhaar
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/login")
async def login(aadhaar: str = Form(...), mobile: str = Form(...), otp: str = Form(...)):
    if aadhaar == dummy_user["aadhaar"] and mobile == dummy_user["mobile"] and otp == dummy_user["otp"]:
        access_token = create_access_token(data={"sub": aadhaar}, expires_delta=timedelta(minutes=30))
        return JSONResponse(content={"message": "Login successful", "token": access_token})
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/dashboard")
async def dashboard(current_user: str = Depends(get_current_user)):
    return {"message": f"Welcome to your dashboard, Aadhaar: {current_user}"}
