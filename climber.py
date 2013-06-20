#!/usr/bin/env python

from Exscript.protocols import SSH2, Telnet, Account
from Exscript.util.template import eval_file
import argparse
import getpass
import os
import sys
import time


# Editable paths
PATH_LOGS = '~/climber'
PATH_PLUGINS = 'plugins'

# Terminal colors
INFO = '\033[97m'
DONE = '\033[92m'
ERROR = '\033[91m'
ENDC = '\033[0m'

DEVNULL = open(os.devnull, 'w')


def print_banner():
    header = INFO + '  _________  ___  __       ____                   \n' + ENDC
    header += INFO + '  \_   ___ \|  | |__| _____\_ |__   ___________   \n' + ENDC
    header += INFO + '  /    \  \/|  | |  |/     \| __ \_/ __ \_  __ \  \n' + ENDC
    header += INFO + '  \     \___|  |_|  |  Y Y  \ \_\ \  ___/|  | \/  \n' + ENDC
    header += INFO + '   \______  /____/__|__|_|  /___  /\___  >__|     \n' + ENDC
    header += INFO + '          \/              \/    \/     \/         \n' + ENDC
    header += '   Checks Unix system for privilege escalations   \n' 
    header += INFO + '   --------------------------------------------   \n' + ENDC
    print header


def myparser():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Auditing tool to check system misconfigurations that may allow attackers to escalate privileges.', version='Climber v.1.0 - Powered by Raffaele Forte')
   
    group = parser.add_argument_group('connection')
    group.add_argument('--host', action="store", help='set hostname or ip')
    group.add_argument('--port', type=int, help='set port number')
    group.add_argument('--ssh', action='store_true', help='set ssh connection')
    group.add_argument('--telnet', action='store_true', help='set telnet connection')
    
    group = parser.add_argument_group('authentication')
    group.add_argument('--username', action="store", help='set username')
    group.add_argument('--password', action="store", help='set password')
    
    group = parser.add_argument_group('plugins')
    group.add_argument('--category', action='store', help='set category')
    group.add_argument('--plugin', action='store', help='set plugin')
        
    return parser.parse_args()
    

def save_logs(text, path, filename):
    # Make directories
    logs = os.path.expanduser(path)
    if not os.path.exists(logs):
        os.makedirs(logs)
    # Write mode creates a new file or overwrites the existing content of the file.
    try:
        f = open(logs + '/' + filename, 'w')
        try:
            # Write a sequence of strings to a file
            f.writelines(text)
        finally:
            f.close()
    except Exception, e:
        sys.exit(ERROR + '\n[!] ' + str(e) + '\n' + ENDC)
        

def list_plugins(path):
    try:
        plugins = os.listdir(path)
        plugins.sort()
        return plugins
    except Exception, e:
        sys.exit(ERROR + '\n[!] ' + str(e) + '\n' + ENDC)
        

def run_plugin(conn, logs, category, plugin):
    
    path = logs + '/' + category
    
    try:
        eval_file(conn, PATH_PLUGINS + '/' + category + '/' + plugin, foobar=None)      
        save_logs(conn.response, path, plugin + '.log')        
        print '  %-20s' % (plugin) + '[' + DONE + 'ok' + ENDC + ']'       
    except:
        print '  %-20s' % (plugin) + '[' + ERROR + 'ko' + ENDC + ']'


def main():
 
    args = myparser()
    print_banner()
    
    host = args.host
    port = args.port 
    username = args.username
    password = args.password
    ssh = args.ssh
    telnet = args.telnet
    category = args.category
    plugin = args.plugin
    
    if host == None:
        host = raw_input(INFO + '[+]' + ENDC + ' Enter hostname or ip ' + INFO + '> ' + ENDC)
        
    if (ssh == False) and (telnet == False):     
        connection = raw_input(INFO + '[+]' + ENDC + ' Enter connection type ' + INFO + '> ' + ENDC)
        if connection.lower() == 'ssh':
            ssh = True
        elif connection.lower() == 'telnet':
            telnet = True
            
    if username == None:
        username = raw_input(INFO + '[+]' + ENDC + ' Enter username ' + INFO + '> ' + ENDC)
    if password == None:
        password = getpass.getpass(INFO + '[+]' + ENDC + ' Enter password ' + INFO + '> ' + ENDC)

        
    account = Account(username, password)
    
    if ssh:
        conn = SSH2()
    elif telnet:
        conn = Telnet()
    else:
        sys.exit(ERROR + '\n[!] Set connection type: (ssh|telnet)\n' + ENDC)
        
    conn.connect(host, port)
    conn.login(account)
    
    # Print info about used Exscript driver
    driver = conn.get_driver()
    print INFO + '\n[i] Using driver: ' + ENDC + driver.name
    
    logs = PATH_LOGS + '/' + host + '-' + str(int(time.time()))
    
    if plugin and (category == None):
        sys.exit(ERROR + '\n[!] Set category: -C CATEGORY\n' + ENDC)
    
    if category:
        print INFO + '\n[i] Plugins category: ' + ENDC + category + '\n'
        if plugin:
            run_plugin(conn, logs, category, plugin)
        else:
            for p, plugin in enumerate(list_plugins(PATH_PLUGINS + '/' + category)):
                run_plugin(conn, logs, category, plugin)
     
    if (category == None) and (plugin == None):
        for c, category in enumerate(list_plugins(PATH_PLUGINS)):
            print INFO + '\n[i] Loading plugins: ' + ENDC + category + '\n'
            for p, plugin in enumerate(list_plugins(PATH_PLUGINS + '/' + category)):
                run_plugin(conn, logs, category, plugin)

    conn.send('exit\r')
    conn.close()
        
    print INFO + '\n[i] Logs saved in ' + PATH_LOGS + '\n' + ENDC

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt, e:
        sys.exit(ERROR + '\n\n[!] Quitting...\n' + ENDC)
