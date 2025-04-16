from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Allow all origins for simplicity (in production, restrict this to only your frontend's origin)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins, or specify the frontend URL, like 'http://localhost:5500'
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)

# Dummy user data (replace with real data in production)
dummy_user = {
    "aadhaar": "111111111111",  # Dummy Aadhaar number
    "mobile": "9876543210",       # Dummy mobile number
    "otp": "123456"               # Dummy OTP
}

@app.post("/login")
async def login(aadhaar: str = Form(...), mobile: str = Form(...), otp: str = Form(...)):
    # Simulate authentication check
    if aadhaar == dummy_user["aadhaar"] and mobile == dummy_user["mobile"] and otp == dummy_user["otp"]:
        # Return success response
        return JSONResponse(content={"message": "Login successful ra"})
    else:
        # Return error response
        raise HTTPException(status_code=401, detail="Authentication failed")
