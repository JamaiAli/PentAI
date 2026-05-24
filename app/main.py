from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from .routes import analyze
import os

app = FastAPI(
    title="PentAI API",
    description="Intelligent vulnerability prioritization and scan analysis API.",
    version="1.0.0"
)

# Include core routing
app.include_router(analyze.router)

# Configuration du dossier static pour le frontend
static_path = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_path, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_path), name="static")

@app.get("/")
def read_root():
    """ Serve the main UI dashboard """
    index_file = os.path.join(static_path, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Welcome to the PentAI API. UI is not built yet."}
