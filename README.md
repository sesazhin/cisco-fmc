# cisco-fmc
Scripts for communication with Cisco FMC via API
These scripts have been written and tested with Python 3.10 but should work with Python 3.6 and newer versions as well.<br>
They're is only supported on Windows (might work on Linux and macOS but haven't been tested there).

## /scripts/fmc_acp_logging.py
What this script does:
1. Takes Access Control Policy (ACP) name.
2. Gets all access control rules for a specified ACP.
3. Disables or enables logging in all* rules for a specified ACP.<br>
\*those rules that already have logging configured in a right way - skipped

For required libraries and their versions see **requirements.txt**.

## How to use /scripts/fmc_acp_logging.log
1. Start from cloning script to your system:
`git clone https://github.com/sesazhin/cisco-fmc.git`

2. Install required libraries using requirements,txt file:
`pip3.exe install -r requirements.txt`

3. Make changes in the configuration file: **/scripts/config.py** (for guidance, see comments and examples in **config.py**)

4. Run the script: 
`python.exe fmc_acp_logging.log`

## /scripts/fmc_remove_time_ranges.py
What this script does:
1. Gets all time-ranges from file with ASA's configuration (**file_to_parse_name**). ASA's configuration contains all time-ranges that has to be removed from FMC.
2. Gets all time-ranges from FMC.
3. Removes all time-ranges from FMC that exists on ASA (if some time-range is used by device on FMC - it's skipped and script proceeds to the next time-range).
