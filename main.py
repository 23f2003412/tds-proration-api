from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


app = FastAPI(title="Proration Calculator")


class ChargeRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: float
    days_in_actual_month: float
    spec: str


@app.post("/charge")
def calculate_charge(payload: ChargeRequest) -> dict[str, float]:
    """Calculate the plan-price difference prorated under the requested spec."""
    if payload.spec == "v1":
        divisor = 30
    elif payload.spec == "v2":
        divisor = payload.days_in_actual_month
        if divisor <= 0:
            raise HTTPException(status_code=400, detail="days_in_actual_month must be positive")
    else:
        raise HTTPException(status_code=400, detail="spec must be 'v1' or 'v2'")

    return {"charge": (payload.new_price - payload.old_price) * (payload.days_remaining / divisor)}


@app.get("/")
def health() -> dict[str, str]:
    return {"status": "ok", "endpoint": "POST /charge"}
