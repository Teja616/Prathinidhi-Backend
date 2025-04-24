import firebase_admin
from firebase_admin import credentials, firestore
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi import UploadFile, File
from fastapi.responses import JSONResponse
from jose import jwt, JWTError
from datetime import datetime, timedelta
from typing import Optional
from fastapi.responses import FileResponse
from pydantic import BaseModel
import requests
import os

# === CONFIG ===
SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# === APP INITIALIZATION ===
app = FastAPI()
auth_scheme = HTTPBearer()

# === CORS ===
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === FIREBASE SETUP ===

FIREBASE_CRED_PATH = os.getenv("FIREBASE_CRED_PATH")

if FIREBASE_CRED_PATH:
    cred = credentials.Certificate(FIREBASE_CRED_PATH)
    firebase_admin.initialize_app(cred)
    db = firestore.client()
else:
    raise ValueError("FIREBASE_CRED_PATH environment variable not set")

# === JWT UTILS ===
def create_access_token(data: dict, expires_delta=None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

# === SESSION STORE ===
session_tokens = {}

# === DEPENDENCY ===
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

# Custom 404 handler
@app.exception_handler(404)
async def custom_404_handler(request: Request, exc):
    file_path = os.path.join("static", "er404.html")
    return FileResponse(file_path, status_code=404)

@app.post("/login")
async def login(data: dict):
    aadhaar = data.get("aadhaar")
    mobile = data.get("mobile")
    otp = data.get("otp")

    # Retrieve users from Firebase Firestore
    users_ref = db.collection("users")
    docs = users_ref.stream()

    for doc in docs:
        user = doc.to_dict()
        if user["aadhaar"] == aadhaar and user["mobile"] == mobile and user["otp"] == otp:
            token = create_access_token({"aadhaar": aadhaar})
            session_tokens[aadhaar] = token
            return {"token": token, "message": "Login successful"}
    
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/dashboard")
async def get_dashboard(user=Depends(get_current_user)):
    aadhaar = user.get("aadhaar")
    # Retrieve user from Firebase Firestore
    user_ref = db.collection("users").document(aadhaar)
    user_doc = user_ref.get()
    
    if user_doc.exists:
        return {"user": user_doc.to_dict()}
    else:
        raise HTTPException(status_code=404, detail="User not found")

@app.post("/complaint")
async def file_complaint(data: dict, user=Depends(get_current_user)):
    aadhaar = user.get("aadhaar")
    
    complaint = {
        "applicationType": data.get("applicationType"),
        "receivedThrough": data.get("receivedThrough"),
        "problemSummary": data.get("problemSummary"),
        "religion": data.get("religion"),
        "caste": data.get("caste"),
        "occupation": data.get("occupation"),
        "timestamp": datetime.utcnow().isoformat()
    }

    # Retrieve user from Firebase Firestore
    user_ref = db.collection("users").document(aadhaar)
    user_doc = user_ref.get()
    
    if user_doc.exists:
        user_data = user_doc.to_dict()
        complaints = user_data.get("complaints", [])
        complaints.append(complaint)
        
        # Update the user's complaints in Firebase Firestore
        user_ref.update({"complaints": complaints})
        
        return {"message": "Complaint filed successfully", "complaint": complaint}
    else:
        raise HTTPException(status_code=404, detail="User not found")


@app.post("/upload")
async def upload_image(file: UploadFile = File(...)):
    # Validate file type (only allow PNG and JPG images)
    if file.content_type not in ["image/png", "image/jpeg"]:
        raise HTTPException(status_code=400, detail="Invalid file type. Only PNG and JPG are allowed.")
    
    # Initialize Firebase Storage bucket (if not already done)
    bucket = storage.bucket()  # This will use the default bucket (you can specify your bucket name here)

    # Define the path where the file will be stored in Firebase Storage
    file_path = f"uploads/{file.filename}"

    # Upload the file to Firebase Storage
    blob = bucket.blob(file_path)

    # Upload the file content to the blob
    try:
        blob.upload_from_file(file.file, content_type=file.content_type)
        # Make the file publicly accessible (optional)
        blob.make_public()

        # Return the public URL of the uploaded image
        return JSONResponse(content={"message": "File uploaded successfully", "file_url": blob.public_url})
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File upload failed: {str(e)}")

# === NEW TTS ROUTE ===

# Define the request model for TTS
class TTSRequest(BaseModel):
    audio: str  # Base64 encoded audio content
    language: str  # Language code (te, hi, en, ta, bn)

# Map of language codes to their corresponding service IDs
SERVICE_ID_MAP = {
    'te': 'bhashini/iitm/asr-dravidian--gpu--t4',
    'hi': 'ai4bharat/conformer-hi-gpu--t4',
    'ta': 'bhashini/iitm/asr-dravidian--gpu--t4',
    'en': 'ai4bharat/whisper-medium-en--gpu--t4',
    'bn': 'bhashini/iitm/asr-indoaryan--gpu--t4'
}

# Get Bhashini API auth token from environment variable
BHASHINI_AUTH_TOKEN = os.getenv("BHASHINI_AUTH_TOKEN")
if not BHASHINI_AUTH_TOKEN:
    print("Warning: BHASHINI_AUTH_TOKEN environment variable not set")

@app.post("/tts")
async def process_audio(request_data: TTSRequest, user=Depends(get_current_user)):
    try:
        # Validate language code
        if request_data.language not in SERVICE_ID_MAP:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid language code. Supported codes: {', '.join(SERVICE_ID_MAP.keys())}"
            )
        
        if not BHASHINI_AUTH_TOKEN:
            raise HTTPException(
                status_code=500,
                detail="Bhashini API token not configured"
            )
            
        # Get the appropriate service ID based on language
        service_id = SERVICE_ID_MAP[request_data.language]
        
        # Prepare the request body for Bhashini API
        bhashini_request_body = {
            "pipelineTasks": [
                {
                    "taskType": "asr",
                    "config": {
                        "language": {
                            "sourceLanguage": request_data.language
                        },
                        "serviceId": service_id,
                        "audioFormat": "wav",
                        "samplingRate": 16000,
                        "postprocessors": [
                            "itn"
                        ]
                    }
                }
            ],
            "inputData": {
                "audio": [
                    {
                        "audioContent": request_data.audio  # Base64 content from frontend
                    }
                ]
            }
        }
        
        # Make API request to Bhashini
        response = requests.post(
            'https://dhruva-api.bhashini.gov.in/services/inference/pipeline',
            json=bhashini_request_body,
            headers={
                'Content-Type': 'application/json',
                'Authorization': BHASHINI_AUTH_TOKEN
            },
            timeout=30  # Set timeout to 30 seconds
        )
        
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Bhashini API error: {response.text}"
            )
            
        # Extract text from Bhashini response
        response_data = response.json()
        
        # Extract the ASR output text from the response
        try:
            output_text = response_data.get("pipelineResponse", {}) \
                          .get("outputs", {}) \
                          .get("asr", [])[0] \
                          .get("source", "")
            
            return {"text": output_text}
        except (KeyError, IndexError, TypeError):
            raise HTTPException(
                status_code=500,
                detail="Invalid response format from Bhashini API"
            )
            
    except requests.RequestException as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error communicating with Bhashini API: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Unexpected error: {str(e)}"
        )

# Run the application with uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
