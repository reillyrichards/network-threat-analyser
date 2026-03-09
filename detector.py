import time #Used to get current timestamps
from collections import defaultdict #Dictionary that auto-creates missing keys
from config import (
    PORT_SCAN_THRESHOLD, PORT_SCAN_TIME,
    BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_TIME,
    HIGH_TRAFFIC_THRESHOLD, HIGH_TRAFFIC_TIME,
    SUSPICIOUS_PORTS
)
from logger import logAlert

class ThreatDetector:
    """
    We use a class to maintain state (history of packages seen) across many function calls.
    Class instance stores data in self and keeps it as long as the program runs
    Alternatively, we could use another function to store the history, but that would be less efficient.
    defaultdict(list) automatically creates an empty list for any new key, so we can append without checking first
    """

    def __init__(self):
        """
        Three dictionaries, one for each type of detection (port scan, brute force, high traffic)
        """
        
        self.port_activity = defaultdict(list) #Stores which ports each IP has hit, with timestamps, each entry contains a tuple of (port_number, timestamp)

        self.ssh_attempts = defaultdict(list) #Stores timestamps of SSH connection attempts per IP (anotehr tuple, always expects timestamp to be the last element)

        self.packet_counts - defaultdict(list) #Stores  timestamps of every packet from each IP.

    def _clean_old_events(self, event_list, time):
        """
        Used to remove any events that are too old to be relevant, don't want the code to run slower each time
        Also, a port scan 10 mins ago shouldn't count towards a port scan happening now

        starts with _ to tell python it should not be called outside this class

        """
        


