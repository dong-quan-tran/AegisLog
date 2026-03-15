from fastapi import FastAPI

app = FastAPI(title="AegisLog")

@app.get("/health")
def health():
    return {"status": "ok", "version": "0.1.0"}
