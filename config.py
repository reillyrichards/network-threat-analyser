#config.py 

#If one IP hits THRESHOLD within the TIME window, flag it as a port scan
PORT_SCAN_THRESHOLD = 10 #Number of unique ports
PORT_SCAN_TIME = 5 #Seconds

#If one IP makes THRESHOLD attempts within TIME, flag as brute force
BRUTE_FORCE_THRESHOLD = 5 #nAttempts
BRUTE_FORCE_TIME = 10 #Seconds

#If one IP sends THRESHOLD packets within TIME. flag it as potential DOS 
HIGH_TRAFFIC_THRESHOLD = 100 #nPackets
HIGH_TRAFFIC_TIME = 5 #Seconds

#Suspicious ports to scan, always flag the following:
SUSPICIOUS_PORTS = [4444, 1337, 31337, 6666, 9999]
#4444 = Common metasploit reverse shell port
#1337, 31337 = Historically assossiated with hacking tools (nmap, ADMworm, etc)
#6666, 9999 = Commonly used in RATs and backdoors

#Network interface to sniff, starting with "lo" for testing but will switch to "eth0" later
INTERFACE = "lo"

#Log file path
LOG_FILE = "logs/alerts.log"
