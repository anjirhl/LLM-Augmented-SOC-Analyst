import os
import json
import requests
import streamlit as st
import pandas as pd
import splunklib.client as client
import splunklib.results as results
from qdrant_client import QdrantClient
from qdrant_client.models import VectorParams, Distance, PointStruct
import time
from sentence_transformers import SentenceTransformer
from dotenv import load_dotenv
import re

# Load environment variables from .env file at startup
load_dotenv()

# Initialize embedding model and Qdrant client
embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
qdrant_client = QdrantClient(host="localhost", port=6333)

# ---------------------------
# Utility Functions
# ---------------------------

def connect_splunk():
    try:
        service = client.connect(
            host=os.getenv("SPLUNK_HOST", "localhost"),
            port=int(os.getenv("SPLUNK_PORT", 8089)),
            username=os.getenv("SPLUNK_USERNAME", "admin"),
            password=os.getenv("SPLUNK_PASSWORD", "Admin@12345"),
            scheme="https"
        )
        return service
    except Exception as e:
        st.error(f"Error connecting to Splunk: {e}")
        return None

def run_saved_search(service, search_name):
    try:
        job = service.jobs.create(f'| savedsearch "{search_name}"')
        while not job.is_done():
            time.sleep(1)
        csv_results = job.results(output_mode="csv")
        df = pd.read_csv(csv_results)
        return df
    except Exception as e:
        st.error(f"Error running saved search '{search_name}': {e}")
        return pd.DataFrame()

def load_json_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        st.error(f"Error loading {path}: {e}")
        return []

def ensure_collection(client, name, dim=384):
    try:
        client.get_collection(name)
    except:
        client.recreate_collection(
            collection_name=name,
            vectors_config=VectorParams(size=dim, distance=Distance.COSINE)
        )

def get_context_preview(context_entry):
    if not isinstance(context_entry, list):
        return ""
    lines = []
    for c in context_entry:
        source = c.get('source', 'src')
        title = c.get('title', '')
        score = c.get('score', 0)
        snippet = c.get('content', '')[:100].replace('\n', ' ')
        lines.append(f"[{source}] {title} ({score:.2f}): {snippet}")
    return "\n".join(lines)

# ---------------------------
# Enrichment & Classification Functions
# ---------------------------

def enrich_alerts_with_context(alerts_df):
    """
    For each alert's command_line, compute embedding, search qdrant soc_kb collection
    for top 5 contextual matches, and add to alert's context list.
    Returns a new DataFrame with 'context' column of list(dict).
    """
    context_results = []
    for cmd_line in alerts_df["command_line"]:
        vec = embedding_model.encode(cmd_line).tolist()
        search_results = qdrant_client.search(
            collection_name="soc_kb",
            query_vector=vec,
            limit=5
        )
        contexts = [r.payload | {"score": r.score} for r in search_results]
        context_results.append(contexts)
    alerts_df = alerts_df.copy()
    alerts_df["context"] = context_results
    return alerts_df

def llm_classify_alert(alert):
    """
    Given an alert with context (list of dicts), form a prompt and send to LLM API to classify
    as True Positive or False Positive with explanation.
    Returns classification string (or error).
    """
    context = alert.get('context', [])
    ctx_text_lines = []
    for x in context:
        source = x.get('source', 'UnknownSource')
        title = x.get('title', 'NoTitle')
        score = x.get('score', 0)
        content_preview = x.get('content', '')[:300].replace('\n', ' ')
        ctx_text_lines.append(f"[{source}] {title} - {score:.2f}\n{content_preview}")
    ctx_text = "\n".join(ctx_text_lines)
    prompt = f"""
Given the alert below:
Alert Type: {alert.get('alert_type', '')}
Command Line: {alert.get('command_line', '')}
Parent Process: {alert.get('parent_process', '')}
Tags: {alert.get('tags','')}
Context:
{ctx_text}

1. Classify as True Positive or False Positive and Explain Why?
2. Map the Alert to MITRE ATT&CK Frameworks' Tactics and Techniques
""".strip()
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3",
                "prompt": prompt,
                "stream": False,
                "temperature": 0.3
            },
            timeout=60
        )
        if response.status_code == 200:
            return response.json().get("response", "").strip()
        else:
            return f"Error: {response.status_code} - {response.text}"
    except Exception as e:
        return f"Error: {str(e)}"

# ---------------------------
# Tabs
# ---------------------------

def siem_integration_tab():
    st.header("🔗 SIEM Integration")
    service = connect_splunk()
    if not service:
        return
    st.success("Connected to Splunk")
    st.markdown("### Data Status")
    st.write(f"Alerts: {'✅ Loaded' if not st.session_state.alerts_df.empty else '❌ Not Loaded'}")
    st.write(f"Analyst Notes: {'✅ Loaded' if not st.session_state.notes_df.empty else '❌ Not Loaded'}")
    alert_search = st.text_input("Enter Saved Search for SIEM Alerts", "SIEM Alerts")
    if st.button("Run SIEM Alerts Search"):
        df = run_saved_search(service, alert_search)
        if not df.empty:
            st.session_state.alerts_df = df
            st.success(f"Loaded {len(df)} SIEM Alerts")
            st.dataframe(df)
    notes_search = st.text_input("Enter Saved Search for Analyst Notes", "SOC Analyst Notes")
    if st.button("Run Analyst Notes Search"):
        df = run_saved_search(service, notes_search)
        if not df.empty:
            st.session_state.notes_df = df
            st.success(f"Loaded {len(df)} Analyst Notes")
            st.dataframe(df)

def knowledge_base_tab():
    st.header("Build Knowledge Base")
    mitre_status = "✅ Loaded" if not st.session_state.mitre_data.empty else "❌ Not Loaded"
    lolbas_status = "✅ Loaded" if not st.session_state.lolbas_data.empty else "❌ Not Loaded"
    st.write(f"MITRE: {mitre_status}")
    st.write(f"LOLBAS: {lolbas_status}")
    if st.button("Load MITRE & LOLBAS"):
        mitre = load_json_file("data/mitre_attack.json")
        lolbas = load_json_file("data/lolbas.json")
        # Optional: Add privilege escalation KB if available 
        # priv_esc = load_json_file("data/priv_esc.json")
        if mitre:
            st.session_state.mitre_data = pd.DataFrame(mitre)
            st.success(f"Loaded MITRE ({len(st.session_state.mitre_data)}) records from local file")
        else:
            st.error("Failed to load MITRE data from local file")
        if lolbas:
            st.session_state.lolbas_data = pd.DataFrame(lolbas)
            st.success(f"Loaded LOLBAS ({len(st.session_state.lolbas_data)}) records from local file")
        else:
            st.error("Failed to load LOLBAS data from local file")
        # Uncomment if privilege escalation KB available
        # if priv_esc:
        #     st.session_state.priv_esc_data = pd.DataFrame(priv_esc)
        #     st.success(f"Loaded Privilege Escalation ({len(st.session_state.priv_esc_data)}) records from local file")
        # else:
        #     st.error("Failed to load Privilege Escalation data from local file")

def contextual_enrichment_tab():
    st.header("🔎 Contextual Enrichment")
    if st.session_state.alerts_df.empty:
        st.warning("⚠️ No SIEM Alerts loaded")
        return
    if st.session_state.notes_df.empty:
        st.warning("⚠️ No Analyst Notes loaded")
        return
    if st.session_state.mitre_data.empty and st.session_state.lolbas_data.empty:
        st.warning("⚠️ No Knowledge Base loaded (MITRE/LOLBAS)")
        return
    if st.button("Run Contextual Enrichment"):
        try:
            client = qdrant_client
            ensure_collection(client, "soc_kb")
            kb_texts = []
            if not st.session_state.mitre_data.empty and "description" in st.session_state.mitre_data:
                kb_texts += st.session_state.mitre_data["description"].astype(str).tolist()
            if not st.session_state.lolbas_data.empty and "Description" in st.session_state.lolbas_data:
                kb_texts += st.session_state.lolbas_data["Description"].astype(str).tolist()
            # Optional: Add privilege escalation context if implemented
            # if "priv_esc_data" in st.session_state and not st.session_state.priv_esc_data.empty:
            #     kb_texts += st.session_state.priv_esc_data["description"].astype(str).tolist()
            points = [PointStruct(id=i, vector=[0.0] * 384, payload={"source": "kb", "title": f"KB Entry {i+1}", "content": txt}) for i, txt in enumerate(kb_texts)]
            client.upsert(collection_name="soc_kb", points=points)
            st.success("Knowledge base indexed into Qdrant")
            alerts_df = st.session_state.alerts_df
            enriched_df = enrich_alerts_with_context(alerts_df)
            st.session_state.alerts_df = enriched_df
            # Show sample enrichment as preview table
            if not enriched_df.empty:
                st.markdown("### Sample alerts with context preview (top 10)")
                preview_df = enriched_df.head(10).copy()
                preview_df["context"] = preview_df["context"].apply(get_context_preview)
                st.dataframe(preview_df)
        except Exception as e:
            st.error(f"Error during contextual enrichment: {e}")

def classification_tab():
    st.header("🤖 Alert Classification with Local LLM")

    if st.session_state.alerts_df.empty:
        st.warning("⚠️ No SIEM Alerts loaded")
        return

    batch_sizes = [5, 25, 50, 100]
    batch_size = st.selectbox(
        "Batch size",
        options=batch_sizes,
        format_func=lambda x: f"{x} alerts" if x != len(st.session_state.alerts_df) else "All alerts"
    )

    # Randomize the alerts for classification
    alerts_to_classify = st.session_state.alerts_df.sample(n=min(batch_size, len(st.session_state.alerts_df)))

   # st.write(f"Randomly selected {len(alerts_to_classify)} alerts for classification:")

    if st.button("Classify Selected Alerts with Local LLM"):
        try:
            client = qdrant_client
            ensure_collection(client, "classified_alerts")
            classified = []
            total = len(alerts_to_classify)
            progress_bar = st.progress(0, text="Classifying alerts...")

            for idx, (_, row) in enumerate(alerts_to_classify.iterrows()):
                alert_dict = row.to_dict()
                classification = llm_classify_alert(alert_dict)
                alert_dict["classification"] = classification
                classified.append(alert_dict)
                progress_bar.progress((idx + 1) / total, text=f"Classifying ({idx+1}/{total})")

            df_classified = pd.DataFrame(classified)
            st.session_state.classified_df = df_classified

            points = [PointStruct(id=i, vector=[0.0] * 384, payload=rec) for i, rec in enumerate(classified)]
            client.upsert(collection_name="classified_alerts", points=points)

            st.success("Alerts classified and stored in Qdrant")

            df_display = df_classified.copy()
            df_display["context"] = df_display["context"].apply(get_context_preview)
            st.dataframe(df_display)

        except Exception as e:
            st.error(f"Error classifying alerts: {e}")



def llm_interactive_search_tab():
    st.header("💬 LLM Interactive Search")
    st.write("Interact with your local AI assistant. Ask your questions below and submit.")
    if "llm_chat_history" not in st.session_state:
        st.session_state.llm_chat_history = []
    query = st.text_area("Enter your message:")
    if st.button("Submit Prompt"):
        prompt = query.strip()
        injected = False
        alert_id_match = re.search(r'ALRT-\d{4}-\d{4}', prompt)
        if alert_id_match and "alerts_df" in st.session_state and not st.session_state.alerts_df.empty:
            alert_id = alert_id_match.group(0)
            df = st.session_state.alerts_df
            match_rows = df[df.get("alert_id", "") == alert_id]
            if not match_rows.empty:
                alert = match_rows.iloc[0].to_dict()
                context_pretty = get_context_preview(alert.get("context", []))
                prompt = f"""Given the alert below:
Alert ID: {alert.get('alert_id')}
Alert Type: {alert.get('alert_type', '')}
Command Line: {alert.get('command_line', '')}
Parent Process: {alert.get('parent_process', '')}
Description: {alert.get('description', '')}
Context:
{context_pretty}

Help analyst with the following questions

1. Classify as True Positive or False Positive. Explain why.
2. Map the alert with MITRE ATT&CK Tactics and Techniques.
"""
                injected = True
        try:
            resp = requests.post(
                "http://localhost:11434/api/generate",
                json={"model": "llama3", "prompt": prompt, "stream": False},
                timeout=60
            )
            if resp.status_code == 200:
                answer = resp.json().get("response", "").strip()
                if not answer:
                    answer = "[No response from LLM]"
            else:
                answer = f"LLM Error: Status code {resp.status_code}"
        except Exception as ex:
            answer = f"Error connecting to LLM: {str(ex)}"
        st.session_state.llm_chat_history.append({"role": "user", "text": query})
        if injected:
            st.session_state.llm_chat_history.append({"role": "llm", "text": "\n" + answer})
        else:
            st.session_state.llm_chat_history.append({"role": "llm", "text": answer})
    for msg in st.session_state.llm_chat_history:
        if msg["role"] == "user":
            st.markdown(f"**You:** {msg['text']}")
        else:
            st.markdown(f"**LLM:** {msg['text']}")

# ---------------------------
# Main
# ---------------------------

def main():
    st.set_page_config(page_title="SOC - AI Analyst App", layout="wide")
    st.title("SOC - AI Analyst App")
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "SIEM Integration",
        "Knowledge Base",
        "Contextual Enrichment",
        "Alert Classification",
        "LLM Interactive Search"
    ])
    with tab1:
        siem_integration_tab()
    with tab2:
        knowledge_base_tab()
    with tab3:
        contextual_enrichment_tab()
    with tab4:
        classification_tab()
    with tab5:
        llm_interactive_search_tab()

if __name__ == "__main__":
    if "alerts_df" not in st.session_state:
        st.session_state.alerts_df = pd.DataFrame()
    if "notes_df" not in st.session_state:
        st.session_state.notes_df = pd.DataFrame()
    if "mitre_data" not in st.session_state:
        st.session_state.mitre_data = pd.DataFrame()
    if "lolbas_data" not in st.session_state:
        st.session_state.lolbas_data = pd.DataFrame()
    if "classified_df" not in st.session_state:
        st.session_state.classified_df = pd.DataFrame()
    if "llm_chat_history" not in st.session_state:
        st.session_state.llm_chat_history = []
    # Optional: st.session_state.priv_esc_data = pd.DataFrame()
    main()
