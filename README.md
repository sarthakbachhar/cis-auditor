# cis-auditor

# Audit Management System

A lightweight web-based application for running and managing security audits.  
This tool allows you to perform **single audits**, **batch audits**, and **scheduled audits** directly from a user-friendly interface. Once an audit is completed, the system generates comprehensive **HTML** and **PDF reports** for review.

---

## 🚀 Features
- Run **single audit** with minimal setup  
- Perform **batch audits** on multiple targets  
- Schedule audits to run automatically at defined times  
- Generate reports in **HTML** and **PDF formats**  
- Simple web-based interface, accessible via any browser  

---

## 📦 Installation & Usage

Follow these steps to get started:

1. **Install Python**  
   Make sure you have Python installed on your system.  
   [Download Python](https://www.python.org/downloads/)

2. **Create & Activate Virtual Environment**
   ```bash
   python -m venv venv
   # On Linux/Mac
   source venv/bin/activate
   # On Windows
   venv\Scripts\activate

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt

4. **Run The Application**
   ```bash
   python web_api.py

5. **Access The Web UI**
   Open your browser and visit:
   ```bash
   http://localhost:5000

## 📖 Usage Guide

Once the UI loads, you will have the following options:

* Single Audit → Run an audit on a single target.

* Batch Audit → Perform audits on multiple targets in one go.

* Schedule Audit → Configure recurring or timed audits.

After an audit completes, you can download the results as:

* HTML Report (interactive, easy to view in a browser)

* PDF Report (printable, shareable format)

## 🛠 Requirements

* Python 3.8+

* Dependencies listed in requirements.txt
