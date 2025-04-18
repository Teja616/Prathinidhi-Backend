from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from datetime import datetime, timedelta

# === CONFIG ===
SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# === APP INITIALIZATION ===
app = FastAPI()
auth_scheme = HTTPBearer()

# === CORS (adjust as needed for deployment) ===
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allow all headers
)

# === DUMMY USER DB ===
dummy_users = [
    {
        "aadhaar": "123456789012",
        "mobile": "9014569376",
        "otp": "4689",
        "name": "Vinay",
        "role": "citizen"
    },
    {
        "aadhaar": "123412341234",
        "mobile": "6281363756",
        "otp": "8848",
        "name": "Sai",
        "role": "citizen"
    },
    {
        "aadhaar": "123412341234",
        "mobile": "8888888888",
        "otp": "1234",
        "name": "Sizzan",
        "role": "citizen"
    }
]

# === IN-MEMORY SESSION STORE ===
session_tokens = {}  # { aadhaar: token }

# === JWT UTILS ===
def create_access_token(data: dict, expires_delta=None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload  # dict with 'aadhaar' key
    except JWTError:
        return None

# === DEPENDENCY FOR AUTH ===
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    token = credentials.credentials
    user_data = verify_token(token)
    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    aadhaar = user_data.get("aadhaar")
    if session_tokens.get(aadhaar) != token:
        raise HTTPException(status_code=401, detail="Session expired or logged in elsewhere")
    
    return user_data

# === ROUTES ===

@app.post("/login")
async def login(data: dict):
    aadhaar = data.get("aadhaar")
    mobile = data.get("mobile")
    otp = data.get("otp")

    for user in dummy_users:
        if user["aadhaar"] == aadhaar and user["mobile"] == mobile and user["otp"] == otp:
            token = create_access_token({"aadhaar": aadhaar})
            session_tokens[aadhaar] = token  # overwrite any previous token
            return {"token": token, "message": "Login successful"}
    
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/dashboard")
async def get_dashboard(user=Depends(get_current_user)):
    aadhaar = user.get("aadhaar")
    for u in dummy_users:
        if u["aadhaar"] == aadhaar:
            return {"user": u}
    
    raise HTTPException(status_code=404, detail="User not found")
