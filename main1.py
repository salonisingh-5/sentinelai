from fastapi import FastAPI
from database import engine, Base

# IMPORT ROUTES
from routes.alerts import router as alerts_router
from routes.logs import router as logs_router

# CREATE FASTAPI APP
app = FastAPI()

# CREATE DATABASE TABLES
Base.metadata.create_all(bind=engine)

# REGISTER ROUTES
app.include_router(alerts_router)
app.include_router(logs_router)


@app.get("/")
def home():
    return {"message": "SentinelAI Backend Running"}