# Secure RAG - setup

1. `pip install -r requirements.txt`
2. **Image / scanned-PDF OCR (optional but recommended)**: install Tesseract.
   Windows: download the installer from https://github.com/UB-Mannheim/tesseract/wiki and keep the default path
   (`C:\Program Files\Tesseract-OCR`), or set the env var `TESSERACT_CMD` to the full path of `tesseract.exe`.
   Without it, images and scanned PDFs are QUARANTINED as unreadable (they never reach the vector database).
3. **Real LLM (optional)** - NVIDIA NIM (get an `nvapi-...` key at https://build.nvidia.com):
   Windows CMD: `set NVIDIA_API_KEY=nvapi-your-key` then run the app in the same window
   (permanent: `setx NVIDIA_API_KEY "nvapi-your-key"` and open a new terminal).
   Default model `meta/llama-3.3-70b-instruct`; pick another with `set LLM_MODEL=<model id from build.nvidia.com>`.
   Anthropic (`ANTHROPIC_API_KEY`) and OpenAI (`OPENAI_API_KEY`) also work; if several keys are set, NVIDIA wins.
   It enables LLM triage of borderline documents and a "Use a real LLM" checkbox on the Ask page.
4. Run: `python run_demo.py` (console) or `python -m dashboard.app` (website at http://127.0.0.1:5000)
5. Tests: `python -m pytest`
