import logging
from config import CyberSourceConfig
from cybersource_auth_capture_single import CyberSourcePayment as CyberSourcePaymentSingle
from cybersource_auth_capture import CyberSourcePayment as CyberSourcePaymentSeparate
from cybersource_auth_reversal import CyberSourceReversal
from cybersource_auth_refund import CyberSourceRefund
from cybersource_decision_manager import CyberSourceDecisionManager

# Setup logging
logging.basicConfig(filename="cybersource_log.txt", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def log_and_print(result, transaction_type):
    """Log results and print them to the console."""
    if result is None:
        result = {"status": "FAILED", "error": "No response received"}
    
    log_message = f"{transaction_type}: {result}"
    logging.info(log_message)
    print(log_message)

def main():
    """Execute all CyberSource transactions in sequence and log results."""
    config = CyberSourceConfig()  # Load API credentials

    # 1️⃣ Perform Authorization & Capture (Single Request)
    cyber_payment_single = CyberSourcePaymentSingle(config)
    auth_result_single = cyber_payment_single.authorize_and_capture_payment()
    log_and_print(auth_result_single, "AUTHORIZATION & CAPTURE (SINGLE)")

    # 2️⃣ Perform Authorization & Capture (Separate Requests)
    cyber_payment_separate = CyberSourcePaymentSeparate(config)
    auth_result_separate = cyber_payment_separate.authorize_payment()  # Call authorization first
    log_and_print(auth_result_separate, "AUTHORIZATION (SEPARATE)")

    # Ensure `auth_result_separate` is a dictionary before accessing keys
    if isinstance(auth_result_separate, dict) and auth_result_separate.get("status") == "SUCCESS":
        transaction_id = auth_result_separate.get("transaction_id")
        capture_result = cyber_payment_separate.capture_payment(transaction_id)  # Capture the payment
        log_and_print(capture_result, "CAPTURE (SEPARATE)")

    # 3️⃣ Perform Reversal (if either authorization was successful)
    for auth_result in [auth_result_single, auth_result_separate]:
        if isinstance(auth_result, dict) and auth_result.get("status") == "SUCCESS":
            transaction_id = auth_result.get("transaction_id")
            cyber_reversal = CyberSourceReversal(config)
            reversal_result = cyber_reversal.process_reversal(transaction_id)
            log_and_print(reversal_result, f"AUTHORIZATION REVERSAL ({auth_result['message']})")

    # 4️⃣ Perform Refund (if either capture was successful)
    for auth_result in [auth_result_single, auth_result_separate]:
        if isinstance(auth_result, dict) and auth_result.get("status") == "SUCCESS":
            transaction_id = auth_result.get("transaction_id")
            cyber_refund = CyberSourceRefund(config)
            refund_result = cyber_refund.refund_payment(transaction_id)
            log_and_print(refund_result, f"REFUND ({auth_result['message']})")

    # 5️⃣ Test Decision Manager (fraud detection)
    cyber_dm = CyberSourceDecisionManager(config)
    dm_result = cyber_dm.test_decision_manager_rejection()
    log_and_print(dm_result, "DECISION MANAGER TEST")

if __name__ == "__main__":
    main()
