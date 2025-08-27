Implementation

The implementation phase translates the design and methodology into a working system that augments SOC operations with LLM-driven intelligence. This chapter elaborates the steps undertaken, technologies deployed, and scripts developed during the project execution. The system is deployed in a modular fashion, beginning with environment preparation, followed by knowledge base construction, data processing pipelines, and finally the classification interface. Each module is detailed below with implementation scripts and supporting explanations.


Environment Setup

The environment consisted of a Windows 11 host with 16 GB RAM and >8 cores, Docker Desktop, and Python 3.13.5 as the core programming language. The following software components were installed and configured and Python dependencies included streamlit, sentence-transformers, qdrant-client, and splunk-sdk. 

1.	Qdrant (v1.15.0): Vector database for knowledge base and alert embeddings.
2.	Ollama (v0.11.4) with LLaMA3 model: Local LLM execution.
3.	Splunk Enterprise (v10.0.0): SIEM ingestion of security events and analyst notes.
4.	Streamlit (v1.48.0): Interactive user interface for SOC analysts.


Knowledge Base Construction

The knowledge base integrates structured repositories like MITRE ATT&CK techniques, LOLBAS commands, and Sigma detection rules, along with SOC analyst notes exported from Splunk. Each entry is converted into a text object and embedded into vectors.This step resulted in a vectorized knowledge base with semantic search capability.

Alert Normalization

SOC alerts from Splunk were normalized into structured JSON with consistent fields: timestamp, event_type, process_name, command_line, and alert_description. Splunk search queries were written to filter relevant events: Splunk Searches that needs to be available with SPL’s designed to pull alert data and historical analyst notes. 
 
interfaces with the Splunk SDK to programmatically pull SOC alerts and corresponding analyst notes. It ensures seamless extraction of raw data from multiple Splunk saved searches. Once retrieved, the alerts undergo a thorough cleaning process to remove noise and inconsistencies. This preprocessing prepares the data for accurate downstream embedding and classification tasks.
 

Embedding Generation

Once the alerts were normalized into a consistent JSON schema, they were processed through the SentenceTransformer embedding model (all-MiniLM-L6-v2). This model transforms unstructured alert text — such as command-line parameters, process names, and tags — into high-dimensional vectors that capture semantic meaning rather than relying on simple keyword overlap. For example, two alerts involving certutil.exe and bitsadmin.exe may use entirely different syntax but still map closely in vector space because both relate to ingress tool transfer.

Batch processing was introduced to handle larger datasets efficiently, reducing the computational overhead of embedding thousands of alerts in real-time SOC pipelines. This design allowed the system to scale horizontally, where multiple embeddings could be generated in parallel without bottlenecking the classification pipeline.

The outcome of this stage was a vectorized representation of alerts, which enabled advanced similarity search, clustering, and anomaly detection. By embedding alerts, the system moved beyond keyword-based detection and into context-aware reasoning, where even obfuscated or slightly altered attack patterns could still be correlated with known tactics.

 
Contextual Retrieval

After embeddings were generated, the next step was contextual retrieval. Each alert embedding was compared against a knowledge base (KB) stored in Qdrant, a vector database optimized for approximate nearest-neighbour (ANN) search. The KB contained structured intelligence sources such as:

1.	MITRE ATT&CK techniques (mapped to Tactics, Techniques, and Procedures),
2.	LOLBAS references,
3.	Privilege Escalation artifacts, and
4.	Sigma rule descriptions for detection guidance.

For every incoming alert, the system performed a Top-k similarity search (typically k = 5–10) to fetch the most semantically relevant entries. This ensured that an alert like “fodhelper.exe launched with registry hijack” was not only identified as Privilege Escalation, but also enriched with relevant MITRE mappings (e.g., T1548.002), adversary behaviours, and defensive recommendations.


LLM Classification

The enriched alerts, coupled with contextual intelligence retrieved from Qdrant, were finally passed to LLaMA3 running on Ollama for classification. Through carefully crafted prompt engineering, the LLM was guided to determine whether an alert was a True Positive (TP) or False Positive (FP), while also mapping it to the correct MITRE ATT&CK technique. This ensured that the LLM’s decisions were rooted in both syntactic (raw command-line features) and semantic (threat intelligence context) reasoning. 
 

User Interface (Streamlit)

To make the pipeline operationally usable, a five-tab user interface was developed. Each tab corresponds to a module of the workflow, ensuring analysts can monitor the process end-to-end while maintaining visibility and control over AI recommendations.

1.	SIEM Integration (data loading)
2.	Knowledge Base status
3.	Contextual enrichment preview
4.	Alert classification results
5.	LLM interactive search
