from pydantic import BaseModel, Field
from typing import Optional

# Input payload for phishing prediction requests.
class EmailIn(BaseModel):
    subject: Optional[str] = None
    body: Optional[str] = None
    raw: Optional[str] = None  # if provided, model uses this instead of subject/body

# API response for predictions.
class PredictOut(BaseModel):
    label: int = Field(..., description="1=phishing, 0=legit")
    probability: float

# Incoming feedback payload (optional feature).
class FeedbackIn(BaseModel):
    prediction_id: Optional[str] = None
    label: int = Field(..., ge=0, le=1)
    subject: Optional[str] = None
    body: Optional[str] = None
    raw: Optional[str] = None
    user: Optional[str] = None
    notes: Optional[str] = None

# Feedback acknowledgement.
class FeedbackOut(BaseModel):
    ok: bool
    id: str
