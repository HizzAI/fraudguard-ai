from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
with open("sample.apk", "wb") as f:
    f.write(b"dummy")

response = client.post(
    "/upload-apk",
    files={"file": ("sample.apk", open("sample.apk", "rb"), "application/vnd.android.package-archive")}
)
print(response.json())
