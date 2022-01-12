# 1. Log Properties: #
# Path to Log file
log_path = 'fmc_acp_logging.log'  # no need to change unless required
# Log level:
#  INFO
#  ERROR
#  DEBUG
log_level = 'INFO'  # no need to change unless required

# 2. FMC details and credentials: #
# IP address of FMC
fmc_ip = ''
fmc_username = ''
fmc_password = ''
# Example:
# fmc_ip = '198.18.1.1'
# fmc_username = 'username'
# fmc_password = 'password'

# 3. ACP name where logging of rules should be updated: #
acp_name = ''
# Example:
# acp_name = 'SECLAB_ACP'

# 4. Logging mode: #
# If 'enable' - logging would be enabled for all rules in ACP acp_name.
# If 'disable' - logging would be disabled:
logging_mode = 'enable'
# Example:
# logging_mode = 'disable'
# logging_mode = 'enable'
