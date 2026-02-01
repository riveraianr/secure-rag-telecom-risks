# rag_core.py - Secure RAG Pipeline Core for Telecom/Satellite Risk Detection

import os
import re
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain.text_splitter import CharacterTextSplitter
from langchain_huggingface import HuggingFacePipeline
from transformers import pipeline

# Step 1: Initialize Embedder (downloads model on first run - local, no API key)
embedder = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2",
    model_kwargs={'device': 'cpu'},  # Change to 'cuda' if you have GPU + torch cuda
    encode_kwargs={'normalize_embeddings': True}
)

# Step 2: Load or build FAISS vector store
if os.path.exists("faiss_telecom_index"):
    vector_store = FAISS.load_local(
        "faiss_telecom_index",
        embedder,
        allow_dangerous_deserialization=True  # Required for loading pickled FAISS indexes
    )
    print("Loaded existing FAISS index!")
else:
    print("Building new FAISS index...")

    # Prepare sample telecom/satellite security documents (mock logs/IOCs)
    raw_docs = [
        "Satellite signal anomaly detected: potential jamming or spoofing attack. IOC: unusual frequency shift at 14:32 UTC.",
        "Vulnerability in ground station config: unpatched firmware CVE-2024-12345 allowing remote code execution.",
        "Threat actor using AI-generated prompts to probe telecom APIs for weak authentication.",
        "Log entry: Unauthorized access attempt to Hughes satellite control interface from IP in high-risk region.",
        "Risk: Data exfiltration via compromised Boost Mobile endpoint; TTP: MITRE ATLAS AML.TA0001 (Adversarial ML evasion)."
    ]

    # Optional: Split into smaller chunks if docs are long
    splitter = CharacterTextSplitter(chunk_size=300, chunk_overlap=50)
    docs = splitter.create_documents(raw_docs)

    # Build FAISS vector store
    try:
        vector_store = FAISS.from_documents(docs, embedder)
        print("Vector store built successfully!")
    except Exception as e:
        print(f"Error building vector store: {e}")
        # Fallback
        texts = [doc.page_content for doc in docs]
        vector_store = FAISS.from_texts(texts, embedder)
        print("Fallback: Built from texts.")

    # Save for future runs
    vector_store.save_local("faiss_telecom_index")
    print("FAISS index saved to disk: faiss_telecom_index/")

# Step 3: Input sanitization (OWASP-inspired)
def sanitize_input(query: str) -> str:
    patterns = [
        r'(?i)(ignore previous|system prompt|jailbreak|dan mode)',
        r'base64|rot13|hex|encoded',
        r'[\U0001F300-\U0001F5FF]'  # Emojis / obfuscation
    ]
    for pat in patterns:
        query = re.sub(pat, '', query)
    return query.strip()

# Step 4: Test retrieval
query = sanitize_input("What telecom risks involve satellite spoofing?")
print(f"\nSanitized Query: {query}")

results = vector_store.similarity_search(query, k=3)

print("\nTop Retrieved Documents:")
for i, doc in enumerate(results, 1):
    print(f"{i}. {doc.page_content}\n   (Metadata: {doc.metadata})")

# Assemble context
context = "\n".join([doc.page_content for doc in results])
print("\nRetrieved Context:\n" + context)

# Step 5: Local LLM generation
generator = pipeline("text-generation", model="gpt2", max_new_tokens=100, device=-1)  # CPU
llm = HuggingFacePipeline(pipeline=generator)

rag_prompt = f"""
You are a telecom/satellite security analyst. Use only the provided context to answer. Do not hallucinate or invent facts.
Context:
{context}

Question: {query}

Secure Answer:
"""

response = llm.invoke(rag_prompt)

print("\nGenerated Secure Response:")
print(response)

# Step 6: Basic output safety check
def check_output_safety(text: str):
    if re.search(r'\bCVE-\d{4}-\d{4,7}\b', text):
        print("Safety warning: Potential hallucinated CVE detected in output.")

check_output_safety(response)