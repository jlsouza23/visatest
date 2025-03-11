# CyberSource Payment Integration

This project integrates with the **CyberSource API** to perform payment transactions, including:
- **Authorization & Capture** (Single and Separate Calls)
- **Payment Reversal**
- **Refund Processing**
- **Decision Manager Fraud Detection**

## 🚀 Setting Up the Environment

### **1️⃣ Install Python and Virtual Environment**
Ensure you have **Python 3.8+** installed. If you don’t have it, download it [here](https://www.python.org/downloads/).

Then, create and activate a virtual environment:

```bash
# Create a virtual environment
python -m venv myenv_visa

# Activate the virtual environment
# On Windows:
myenv_visa\Scripts\activate
# On macOS/Linux:
source myenv_visa/bin/activate
```

### **2️⃣ Install Dependencies**
Once the virtual environment is activated, install the required dependencies:

```bash
pip install -r requirements.txt
```

---

## 🔧 **Configuration**
Before running the project, set up your **CyberSource credentials** in the `config.py` file.

Edit `config.py` and replace with your **merchant credentials**:

```python
class CyberSourceConfig:
    """Stores CyberSource API credentials and environment settings."""
    
    def __init__(self):
        self.request_host = "apitest.cybersource.com"  # Sandbox environment
        self.merchant_id = "your_merchant_id_here"
        self.merchant_key_id = "your_key_id_here"
        self.merchant_secret_key = "your_secret_key_here"
```

🔹 If you don't have CyberSource API credentials, **sign up here**:  
👉 [CyberSource Enterprise Business Center](https://developer.cybersource.com/api/developer-guides/dita-gettingstarted/registration.html)

---

## ▶️ **Running the Application**
To execute all payment operations (authorization, capture, reversal, refund, and fraud detection), run:

```bash
python main.py
```

After execution, logs will be saved in **`cybersource_log.txt`**.

---

## 📂 **Project Structure**
```
📁 visa_teste
 ├── 📄 main.py                      # Main script to run all transactions
 ├── 📄 config.py                    # Configuration file for API credentials
 ├── 📄 cybersource_auth_capture.py   # Separate authorization & capture
 ├── 📄 cybersource_auth_capture_single.py # Single-step authorization & capture
 ├── 📄 cybersource_auth_reversal.py  # Payment authorization reversal
 ├── 📄 cybersource_auth_refund.py    # Payment refund processing
 ├── 📄 cybersource_decision_manager.py # Decision Manager (fraud detection)
 ├── 📄 requirements.txt              # Required Python libraries
 ├── 📄 cybersource_log.txt           # Execution logs
```

---

## ✅ **Example Output**
When running `python main.py`, you should see an output similar to this:

```
Response Code (Auth + Capture): 201
AUTHORIZATION & CAPTURE (SINGLE): {'status': 'SUCCESS', 'transaction_id': '7417262906516849704806', 'message': 'Authorization and capture successful'}
AUTHORIZATION (SEPARATE): {'status': 'SUCCESS', 'transaction_id': '7417264390536877904806', 'message': 'Authorization successful'}
CAPTURE (SEPARATE): {'status': 'SUCCESS', 'message': 'Capture successful'}
AUTHORIZATION REVERSAL: {'status': 'SUCCESS', 'message': 'Reversal successful'}
REFUND: {'status': 'FAILED', 'error': 'INVALID_DATA'}
DECISION MANAGER TEST: {'status': 'SUCCESS', 'message': 'Transaction correctly rejected by Decision Manager'}
```

📌 **If you encounter issues**, check the logs in **`cybersource_log.txt`** for more details.

---

## ❓ **Troubleshooting**
### **I get `ModuleNotFoundError: No module named 'CyberSource'`**
Try reinstalling dependencies:
```bash
pip install -r requirements.txt
```

### **I get an error related to missing credentials**
Ensure your **`config.py`** is properly set with your **merchant credentials**.

### **The transaction fails with `INVALID_DATA`**
- Ensure that the **currency is `BRL`** (Brazilian Real).
- Make sure that the **transaction amount** is valid.
- Confirm that your **merchant account is correctly set up** in CyberSource.

---

## 🤝 **Contributing**
Feel free to fork this project and submit a **pull request** if you want to improve it!

📩 **Questions?** Contact me at `jlsouza23@gmail.com`.

---

## 📜 **License**
This project is licensed under the **MIT License**.
```

