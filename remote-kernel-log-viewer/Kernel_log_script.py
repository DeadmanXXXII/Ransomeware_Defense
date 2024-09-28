import time
import syslog

def log_kernel_event(event_message):
    syslog.syslog(syslog.LOG_INFO, event_message)

if __name__ == "__main__":
    while True:
        log_kernel_event("Encryption key created.")
        time.sleep(10)  # Adjust the frequency as needed
