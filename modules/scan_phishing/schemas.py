from pydantic import BaseModel, Field
from typing import Optional

# Input schema for phishing prediction requests
class EmailIn(BaseModel):
    """Input payload for phishing prediction requests."""
    subject: Optional[str] = None
    body: Optional[str] = None
    raw: Optional[str] = None  # if provided, model uses this instead of subject/body

# Output schema for prediction results
class PredictOut(BaseModel):
    """API response for predictions."""
    label: int = Field(..., description="1=phishing, 0=legit")
    probability: float

# Input schema for feedback submission
class FeedbackIn(BaseModel):
    """Incoming feedback payload (optional feature)."""
    prediction_id: Optional[str] = None
    label: int = Field(..., ge=0, le=1)
    subject: Optional[str] = None
    body: Optional[str] = None
    raw: Optional[str] = None
    user: Optional[str] = None
    notes: Optional[str] = None

# Output schema for feedback acknowledgement
class FeedbackOut(BaseModel):
    """Feedback acknowledgement."""
    ok: bool
    id: str
