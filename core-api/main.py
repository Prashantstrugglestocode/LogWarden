from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from database import engine
import models
from ingest import router as ingest_router
from agent import router as agent_router
from remediation import RemediationRequest, execute_remediation

# Create tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="LogWarden Core API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(ingest_router, prefix="/ingest", tags=["Ingestion"])
app.include_router(agent_router, prefix="/agent", tags=["Agent"])

# Remediation endpoint
@app.post("/remediate")
def remediate(request: RemediationRequest):
    result = execute_remediation(request)
    if result["status"] == "error":
        raise HTTPException(status_code=400, detail=result["message"])
    return result

@app.get("/")
async def root():
    return {"message": "LogWarden Core API is running"}
