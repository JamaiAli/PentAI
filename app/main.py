from fastapi import FastAPI
from .routes import analyze

app = FastAPI(
    title="PentAI API",
    description="Intelligent vulnerability prioritization and scan analysis API.",
    version="1.0.0"
)

# Include core routing
app.include_router(analyze.router)

@app.get("/")
def read_root():
    return {"message": "Welcome to the PentAI API. Visit /docs for more info."}
