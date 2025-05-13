from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
from app.services.predict_service import predict_both

predict_router = APIRouter()

class PredictionRequest(BaseModel):
    data: Dict[str, Any]

@predict_router.post("/submit", summary="Submit data for dual prediction")
async def submit_data(payload: PredictionRequest):
    try:
        result = predict_both(payload.data)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
