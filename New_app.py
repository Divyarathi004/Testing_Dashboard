import re
from io import BytesIO

import pandas as pd
import plotly.express as px
import streamlit as st
from docx import Document
from fpdf import FPDF

st.set_page_config(page_title="Audit Compliance Dashboard", layout="wide")


def load_doc(file):
    return Document(BytesIO(file.getvalue()))


def extract_summary_table(file):
    doc = load_doc(file)
    data = []

    for table in doc.tables:
        for row in table.rows:
            row_data = [cell.text.strip() for cell in row.cells]

            if len(row_data) >= 5 and (
                "Failed" in row_data or "Passed" in row_data or "Partial" in row_data
            ):
                try:
                    data.append(
                        {
                            "Asset": row_data[1],
                            "Vulnerability": row_data[2],
                            "Status": row_data[3],
                            "Recommendation": row_data[4],
                            "Reference": row_data[5] if len(row_data) > 5 else "",
                        }
                    )
                except Exception:
                    continue

    return pd.DataFrame(data)


def classify_compliance_status(status):
    status = str(status).strip().lower()
    if "partial" in status:
        return "Partial Compliance"
    if "fail" in status:
        return "Non-Compliance"
    if "pass" in status:
        return "Full Compliance"
    return "Partial Compliance"


def generate_pdf(summary_text):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, summary_text)
    return pdf.output(dest="S").encode("latin-1")


st.title("Audit Compliance Dashboard")
st.caption(
    "Client-focused summary showing only Full Compliance, Partial Compliance, and Non-Compliance."
)

uploaded_files = st.file_uploader(
    "Upload Audit Report (.docx)",
    type=["docx"],
    accept_multiple_files=True,
)

if not uploaded_files:
    st.info("Upload one or more .docx audit reports to view the compliance summary.")
else:
    all_data = []

    for file in uploaded_files:
        df = extract_summary_table(file)
        if not df.empty:
            df["Source File"] = file.name
            all_data.append(df)

    if not all_data:
        st.warning("No findings were detected in the uploaded reports.")
    else:
        df = pd.concat(all_data, ignore_index=True)
        df["Asset"] = df["Asset"].fillna("Unknown Asset")
        df["Vulnerability"] = df["Vulnerability"].fillna("Unspecified Finding")
        df["Status"] = df["Status"].fillna("Unknown")
        df["Recommendation"] = df["Recommendation"].fillna("")
        df["Reference"] = df["Reference"].fillna("")
        df["Compliance"] = df["Status"].apply(classify_compliance_status)

        full_count = int((df["Compliance"] == "Full Compliance").sum())
        partial_count = int((df["Compliance"] == "Partial Compliance").sum())
        non_count = int((df["Compliance"] == "Non-Compliance").sum())
        total_items = full_count + partial_count + non_count
        compliance_score = round((full_count / total_items) * 100, 2) if total_items else 0