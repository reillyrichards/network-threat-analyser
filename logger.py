#Logger.py

import logging
import os
from config import LOG_FILE

#create logs folder if it doesnt exist already
os.makedirs("logs", exist_ok=True)

#Configure logger, sets up the logging behavior, we want to format it like TIME - SEVERITY - MESSAGE
#As this is common in most logging systems.
logging.basicConfig(
    level=logging.INFO, #used to log everything related to INFO or higher
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)   #handlers tell us where the output is going, LOG_FILE AND in the terminal

logger = logging.getLogger("ThreatAnalyser")

def logAlert(threat_type, src_ip, detail):
    """
    Formatting, as pipe-separating (Type | IP | Detail) to allow modular use later, potentially
    wanting to parse things programmatically, it will be easy to separate the data
    """
    message = f"ALERT | Type: {threat_type} | Source IP: {src_ip} | Detail: {detail}"
    logger.warning(message)

def logInfo(message):
    """This is for logging general information, normal logs that don't appear as potential threats
    """

    logger.info(message)
