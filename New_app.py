import re
from io import BytesIO

import pandas as pd
import plotly.express as px
import streamlit as st
from docx import Document
from fpdf import FPDF

st.set_page_config(page_title="Audit Compliance Dashboard", layout="wide")

st.markdown(
    """
    <style>
    .stApp {
        background: linear-gradient(180deg, #f8f3eb 0%, #f2ede4 100%);
    }

    .hero {
        background: linear-gradient(135deg, rgba(24, 24, 27, 0.96), rgba(120, 53, 15, 0.92));
        color: white;
        border-radius: 22px;
        padding: 28px 32px;
        margin-bottom: 1.2rem;
    }

    .metric-card {
        background: rgba(255, 253, 248, 0.95);
        border: 1px solid #ddd3c3;
        border-radius: 18px;
        padding: 18px 20px;
        min-height: 120px;
        box-shadow: 0 10px 24px rgba(31, 41, 55, 0.06);
    }

    .metric-label {
        color: #6b7280;
        font-size: 0.88rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 0.7rem;
    }

    .metric-value {
        color: #1f2937;
        font-size: 2.2rem;
        font-weight: 800;
        line-height: 1;
        margin-bottom: 0.45rem;
    }

    .metric-note {
        color: #6b7280;
        font-size: 0.95rem;
    }

    .panel {
        background: rgba(255, 253, 248, 0.92);
        border: 1px solid #ddd3c3;
        border-radius: 20px;
        padding: 16px 16px 8px;
        margin-bottom: 1rem;
        box-shadow: 0 10px 24px rgba(31, 41, 55, 0.05);
    }
    </style>
    """,
    unsafe_allow_html=True,
)


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
