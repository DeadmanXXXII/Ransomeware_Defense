Project Layout

kernel-log-viewer/

│
├── syslog/

│   ├── syslog_config.conf

│   └── log_sender.py

│

├── elk/

│   ├── logstash/

│   │   └── logstash.conf

│   ├── elasticsearch/

│   └── kibana/
│
├── graylog/

│   ├── graylog_input.conf

│   └── log_sender.py

│
├── kernel_log_script.py

└── README.md

1. Syslog Configuration

syslog/syslog_config.conf

Configure your Syslog daemon (e.g., rsyslog):

*.* @your_syslog_server:514

syslog/log_sender.py

Python script to send logs to Syslog:

import logging
import logging.handlers
import time

# Configure logging
syslog_handler = logging.handlers.SysLogHandler(address=('your_syslog_server', 514))
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
syslog_handler.setFormatter(formatter)

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(syslog_handler)

# Example function to log kernel events
def log_kernel_event(event_message):
    logger.info(event_message)

# Simulate logging kernel events
if __name__ == "__main__":
    while True:
        log_kernel_event("Encryption key created.")
        time.sleep(10)  # Log every 10 seconds

2. ELK Stack Configuration

elk/logstash/logstash.conf

Logstash configuration to receive logs:

input {
    syslog {
        port => 514
    }
}

filter {
    # Add filters here if needed
}

output {
    elasticsearch {
        hosts => ["http://localhost:9200"]
        index => "kernel-logs-%{+YYYY.MM.dd}"
    }
}

3. Graylog Configuration

graylog/graylog_input.conf

Graylog configuration for Syslog input:

# Create a Syslog input in Graylog web interface
# Configuration in the UI should include: 
# - Title: Syslog Input
# - Port: 514
# - Type: Syslog UDP

graylog/log_sender.py

Similar to the Syslog sender, configure to send logs to Graylog:

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

4. Kernel Logging Script

kernel_log_script.py

This script will call the logging functions:

import time
import syslog

def log_kernel_event(event_message):
    syslog.syslog(syslog.LOG_INFO, event_message)

if __name__ == "__main__":
    while True:
        log_kernel_event("Encryption key created.")
        time.sleep(10)  # Adjust the frequency as needed

5. README.md

Include instructions for setup and configuration:

# Kernel Log Viewer Project

## Overview
This project implements remote kernel log viewing using Syslog, ELK Stack, and Graylog.

## Directory Structure
- **syslog/**: Contains configurations and scripts for Syslog.
- **elk/**: Contains configurations for ELK Stack (Logstash, Elasticsearch, Kibana).
- **graylog/**: Contains configurations and scripts for Graylog.
- **kernel_log_script.py**: Main kernel logging script.

## Setup Instructions
1. **Syslog**: 
   - Configure `syslog/syslog_config.conf` with your Syslog server.
   - Run `syslog/log_sender.py` to start sending logs.

2. **ELK Stack**: 
   - Install and configure ELK Stack.
   - Use `elk/logstash/logstash.conf` for Logstash configuration.
   - Start Logstash to listen for incoming logs.

3. **Graylog**: 
   - Install Graylog and configure a Syslog input through the web interface.
   - Run `graylog/log_sender.py` to start sending logs.

4. **Kernel Logging**:
   - Run `kernel_log_script.py` to log kernel events.

Additional Notes

Adjust server addresses and ports as needed in the scripts and configurations.

Ensure all required services (Syslog, ELK, Graylog) are properly installed and configured on your server.

Test the entire setup to ensure logs are being collected and viewed correctly in your chosen solution.


If you need further customization or additional features, feel free to ask!

