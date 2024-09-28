import logging
import logging.handlers

# Configure logging to send logs to Graylog
graylog_handler = logging.handlers.SysLogHandler(address=('your_graylog_server', 514))
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
graylog_handler.setFormatter(formatter)

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(graylog_handler)

def log_kernel_event(event_message):
    logger.info(event_message)

if __name__ == "__main__":
    while True:
        log_kernel_event("Encryption key created.")
        time.sleep(10)
