# 🛡️ CyberGen Secure RAG Pipeline

**A security layer for Retrieval-Augmented Generation (RAG) systems that detects, sanitizes, and quarantines malicious or sensitive documents before they enter the knowledge base.**

CyberGen helps protect RAG applications from prompt injection, hidden instructions, and sensitive information that could compromise retrieval and AI-generated responses.

## 🚨 Problem Statement

RAG systems retrieve information from external documents to answer user questions. However, malicious documents can contain prompt injections or sensitive data that may influence the language model's responses.

CyberGen introduces a document security layer that inspects content before it reaches the retrieval pipeline.

## 💡 Our Solution

CyberGen analyzes incoming documents, identifies potential threats, and applies security decisions before indexing.

- **Threat Detection:** Identifies suspicious instructions, prompt-injection patterns, hidden content, and potential personally identifiable information (PII).
- **Risk Assessment:** Evaluates detected issues to help determine the appropriate handling of a document.
- **Content Sanitization:** Removes or neutralizes supported unsafe content where appropriate.
- **Quarantine:** Isolates documents that require further inspection.
- **Protected RAG:** Compares responses generated using an unprotected retrieval pipeline with responses using the protected pipeline.
- **LLM-Powered Ask:** Uses an NVIDIA-hosted language model to answer questions based on retrieved context.

## 🏗️ Architecture

```text
         Incoming Documents
                  |
                  v
          Document Ingestion
                  |
                  v
        Detection and Analysis
     +------------+-------------+
     |            |             |
 Prompt Injection Hidden Content PII
     |            |             |
     +------------+-------------+
                  |
                  v
          Risk Assessment
                  |
                  v
        Security Decision Layer
           /             \
          v               v
    Sanitization        Quarantine
          |
          v
    Protected Index
          |
          v
    Secure Retrieval
          |
          v
      LLM Response
```

## 🧰 Technology Stack

- **Language:** Python
- **Web Framework:** Flask
- **Frontend:** HTML, CSS, Jinja templates
- **AI Integration:** NVIDIA-hosted language model
- **Testing:** pytest
- **Security Components:** Document scanning, prompt-injection detection, PII detection, sanitization, and quarantine
- **Version Control:** Git and GitHub

## 📂 Project Structure

```text
CyberGen-Secure-RAG-Pipeline/
├── dashboard/       # Flask application and web interface
├── detection/       # Threat detection and risk scoring
├── ingestion/       # Document loading
├── pipeline/        # Security decisions and RAG workflow
├── samples/         # Demonstration documents
├── tests/           # Pipeline tests
├── data/            # Local demo data and generated artifacts
├── run_demo.py      # Demo entry point
├── requirements.txt # Python dependencies
├── INSTALL.md       # Installation instructions
└── .env.example     # Example configuration
```

## ⚙️ Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/Yansekov/CyberGen-Secure-RAG-Pipeline.git
cd CyberGen-Secure-RAG-Pipeline
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

Follow `INSTALL.md` for any additional setup required by the project.

### 4. Configure environment variables

Create a local `.env` file based on `.env.example` and add your own NVIDIA API key using the variable names expected by the application.

**Never commit `.env` or API keys to GitHub.**

### 5. Run the application

Use the startup command documented in `INSTALL.md`. The demo entry point is `run_demo.py`; check the installation instructions for the intended launch method.

## 🧪 Demonstration

CyberGen includes sample documents representing clean content and different potentially malicious cases, including prompt injection and obfuscated or hidden instructions.

The demonstration compares:

**Unprotected RAG**
- Retrieves context without the document-security layer.
- Can expose the language model to malicious instructions present in retrieved content.

**Protected RAG**
- Applies document inspection and security decisions before retrieval.
- Aims to prevent unsafe instructions from influencing the response.

The current demo has shown the unprotected model identifying a malicious instruction in a sample document, while the protected pipeline returned an answer based on the approved context. This is a demonstration result, not a guarantee that every prompt injection will be blocked.

## 🧪 Testing

Run the test suite from the project root:

```bash
python -m pytest
```

If pytest is not installed:

```bash
pip install pytest
```

## 🔐 Security Considerations

- Treat retrieved documents as untrusted input.
- Keep API keys and secrets in environment variables.
- Review quarantined documents before approving them.
- Validate security decisions and model responses with appropriate tests.
- Do not treat LLM-based detection as a replacement for deterministic security checks and human review.

## 🎯 Project Objective

To demonstrate how a dedicated document-security layer can improve the safety of RAG applications by inspecting potentially malicious or sensitive content before it enters the retrieval workflow.

## 👥 Project Information

**Project:** CyberGen Secure RAG Pipeline  
**Category:** AI Security / Retrieval-Augmented Generation  
**Repository:** [GitHub](https://github.com/Yansekov/CyberGen-Secure-RAG-Pipeline)

---

*Built as a cybersecurity project exploring safer document ingestion and retrieval for AI-powered applications.*
