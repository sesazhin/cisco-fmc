# cisco-fmc
Scripts for communication with Cisco FMC via API

## /scripts/fmc_acp_logging.log
What this script does:
1. Takes Access Control Policy (ACP) name
2. Gets all access control rules for a specified ACP
3. Disables or enables logging in all* rules for a specified ACP
\*those rules that already have logging configured in a right way - skipped

For required libraries and their versions see **requirements.txt**.

This tool has been written and tested with Python 3.10 but should work with Python 3.6 and newer versions as well. The tool is only supported on Windows (it might also work on Linux and macOS but hasn't been tested there).

## How to use /scripts/fmc_acp_logging.log
1. Start from cloning script to your system:
`git clone https://github.com/sesazhin/cisco-fmc.git`

2. Install required libraries using requirements,txt file:
`pip3.exe install -r requirements.txt`

3. Make changes in the configuration file: **/scripts/config.py** (for guidance, see comments and examples in **config.py**)

4. Run the script: 
`python.exe fmc_acp_logging.log`
