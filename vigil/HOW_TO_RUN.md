# How to Run Vigil (Backend + Frontend) on Your Laptop

Follow these steps to run both the Veridian backend and the Vigil frontend on your machine.

---

## Prerequisites

- **Python 3.10+** installed ([python.org](https://www.python.org/downloads/))
- **Run the backend as Administrator** (required for NTFS / C: drive access)

---

## Step 1: Open a terminal (PowerShell or Command Prompt)

- Press `Win + R`, type `powershell`, press Enter.  
- Or open **Command Prompt** or **Windows Terminal**.

---

## Step 2: Start the backend (Veridian API)

1. Go to the backend folder:
   ```powershell
   cd "C:\Users\mynam\OneDrive\Documents\vigil\veridian_backend (3)\veridian_backend"
   ```
   *(Change the path if your `vigil` folder is elsewhere.)*

2. Create a virtual environment (recommended, first time only):
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```
   *(If you get an execution policy error, run: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`)*

3. Install dependencies (first time only):
   ```powershell
   pip install -r requirements.txt
   ```

4. **Run the backend as Administrator:**
   - **Option A:** Right‑click PowerShell → **Run as administrator**, then:
     ```powershell
     cd "C:\Users\mynam\OneDrive\Documents\vigil\veridian_backend (3)\veridian_backend"
     .\venv\Scripts\Activate.ps1
     python main.py
     ```
   - **Option B:** From a normal terminal:
     ```powershell
     cd "C:\Users\mynam\OneDrive\Documents\vigil\veridian_backend (3)\veridian_backend"
     .\venv\Scripts\Activate.ps1
     Start-Process python -ArgumentList "main.py" -Verb RunAs
     ```
     *(A new elevated window will open and run the server.)*

5. Leave this terminal open. When it’s running you should see something like:
   ```text
   INFO:     Uvicorn running on http://0.0.0.0:8000
   VERIDIAN Forensic API starting with admin privileges.
   API docs available at http://localhost:8000/docs
   ```

6. Optional: open **http://localhost:8000/docs** in a browser to confirm the API is up.

---

## Step 3: Start the frontend (Vigil UI)

Open a **second** terminal (no need for Admin).

1. Go to the frontend folder:
   ```powershell
   cd "C:\Users\mynam\OneDrive\Documents\vigil\ChronoTrace\ChronoTrace"
   ```

2. Serve the UI with Python’s built‑in server:
   ```powershell
   python -m http.server 5500
   ```

3. Leave this terminal open. You should see:
   ```text
   Serving HTTP on :: port 5500 ...
   ```

---

## Step 4: Open Vigil in your browser

1. Open a browser (Chrome, Edge, Firefox).
2. Go to: **http://127.0.0.1:5500**
3. You should see the Vigil page (matrix-style background, Home, Live Demo, etc.).

---

## Step 5: Run a scan

1. In the **Live Demo** section, choose **Path type** (Auto / Folder / File).
2. Enter a full path, e.g.:
   - File: `C:\Users\Public\test.txt`
   - Folder: `C:\Users\Public`
3. Click **RUN**.
4. Wait for the scan to finish. Results appear in the terminal output, Source Board, and File Description.

---

## Troubleshooting

| Problem | What to do |
|--------|------------|
| **Port 8000 already in use** | Another app is using 8000. Close the other app or run: `$env:PORT="8001"; python main.py` (then the API is at http://localhost:8001; the frontend would need to be updated to use port 8001, or you free port 8000). |
| **“File not found” for a path that exists** | Run the backend **as Administrator**. |
| **Backend not reachable / Run button does nothing** | Ensure Step 2 shows the server running and **http://localhost:8000/docs** opens. |
| **Page is blank or scripts fail** | Use **http://127.0.0.1:5500** (from Step 3), not opening `index.html` as a file. |

---

## Quick reference

- **Backend API:** http://localhost:8000  
- **API docs:** http://localhost:8000/docs  
- **Frontend (Vigil UI):** http://127.0.0.1:5500  
- **Backend folder:** `vigil\veridian_backend (3)\veridian_backend`  
- **Frontend folder:** `vigil\ChronoTrace\ChronoTrace`
