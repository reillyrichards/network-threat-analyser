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

    def _clean_old_events(self, event_list, window):
        """
        Used to remove any events that are too old to be relevant, don't want the code to run slower each time
        Also, a port scan 10 mins ago shouldn't count towards a port scan happening now

        starts with _ to tell python it should not be called outside this class

        """
        cutoff = time.time() - window
        return [e for e in event_list if e[-1] >= cutoff] #e[-1] because the timestamp is stored last
    
    def check_port_scan(self, src_ip, dst_port):
        """
        Records that this IP just hit this port, with timestamp, throw away any record older than PORT_SCAN_TIME seconds
        Count how many unique ports this ip hit in that window.
        Needs to be unique because multiple packets to the same port is normal (e.g loading a webpage)

        Use a set() to count unique ports because sets automatically deduplicate

        """

        now = time.time()

        self.port_activity[src_ip].append((dst_port, now)) #Append tuple of (port, timestamp) to this IP's history
        self.port_activity[src_ip] = self._clean_old_events(self.port_activity[src_ip], PORT_SCAN_TIME) #Get rid of old
        #events, only care about PORT_SCAN_TIME seconds

        unique_ports = set(port for port, timestamp in self.port_activity[src_ip]) #Extracts just the port numbers to deduplicate

        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            logAlert(
                "PORT SCAN", 
                src_ip,
                f"{len(unique_ports)} unique ports hit in {PORT_SCAN_TIME}s "
                f"-ports: {sorted(unique_ports)}"
                #sorted() so its in numerical order
            )     

        


