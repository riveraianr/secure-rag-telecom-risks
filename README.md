# secure-rag-telecom-risks
Mock telecom logs with entries like {"log": "Satellite signal anomaly detected; potential spoofing", "risk_level": "high", "ttp": "MITRE ATT&amp;CK T1595"}. Anonymize/sanitize to simulate sensitive data handling.

## Running the Secure RAG Demo
python rag_core.py

- Downloads model on first run.
- Builds/loads FAISS index.
- Retrieves relevant telecom risks.
- Generates grounded response (with gpt2 example).

Demo: Run python rag_core.py to see secure query → retrieval → generation. Handles spoofing risks with OWASP mitigations.Demo: Run python rag_core.py to see secure query → retrieval → generation. Handles spoofing risks with OWASP mitigations.
