import sys
from modules.scan_phishing.cli import main as phishing_main

if __name__ == "__main__":
    phishing_main(sys.argv[1:])
