from fastapi import FastAPI
from ingest import router as ingest_router
from agent import router as agent_router

app = FastAPI(title="AI Security Officer API")

from fastapi.middleware.cors import CORSMiddleware
from database import engine
import models

# Create tables
models.Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingest_router, prefix="/ingest", tags=["Ingestion"])
app.include_router(agent_router, prefix="/agent", tags=["Agent"])

@app.get("/")
async def root():
    return {"message": "AI Security Officer API is running"}
