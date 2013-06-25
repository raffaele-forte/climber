#!/usr/bin/env python

from Exscript.protocols import SSH2, Telnet, Account
from Exscript.util.template import eval_file
import argparse
import getpass
import os
import sys
import time


# Editable paths
PATH_LOGS = '~/Climber/logs'
PATH_PLUGINS = 'plugins'

# Terminal colors
BLUE = '\033[34m'
GREEN = '\033[32m'
RED = '\033[31m'
ENDC = '\033[0m'

DEVNULL = open(os.devnull, 'w')


def print_banner():
    header  = BLUE + '  _________  ___  __       ____                   \n' + ENDC
    header += BLUE + '  \_   ___ \|  | |__| _____\_ |__   ___________   \n' + ENDC
    header += BLUE + '  /    \  \/|  | |  |/     \| __ \_/ __ \_  __ \  \n' + ENDC
    header += BLUE + '  \     \___|  |_|  |  Y Y  \ \_\ \  ___/|  | \/  \n' + ENDC
    header += BLUE + '   \______  /____/__|__|_|  /___  /\___  >__|     \n' + ENDC
    header += BLUE + '          \/              \/    \/     \/         \n' + ENDC
    header += '   Checks Unix system for privilege escalations   \n' 
    header += BLUE + '   --------------------------------------------   \n' + ENDC
    print header


def myparser():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Automated auditing tool to check system misconfigurations which may allow attackers to escalate the privileges.', version='Climber v.1.0 - Powered by Raffaele Forte')
   
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
    # Write mode creates a new file or overwrites the existing content of the file
    try:
        f = open(logs + '/' + filename, 'w')
        try:
            # Write a sequence of strings to a file
            splitted_text=text.split('\n')
            f.writelines([item for item in splitted_text[:-1]])

        finally:
            f.close()
    except Exception, error:
        sys.exit(RED + '\n[!] ' + str(error) + '\n' + ENDC)
        

def list_plugins(path):
    try:
        plugins = os.listdir(path)
        plugins.sort()
        return plugins
    except Exception, error:
        sys.exit(RED + '\n[!] ' + str(error) + '\n' + ENDC)
        

def run_plugin(conn, logs, category, plugin):
    
    path = logs + '/' + category
    
    try:
        eval_file(conn, PATH_PLUGINS + '/' + category + '/' + plugin, foobar=None)      
        save_logs(conn.response, path, plugin + '.log')        
        print '  %-20s' % (plugin) + '[' + GREEN + 'ok' + ENDC + ']'       
    except:
        print '  %-20s' % (plugin) + '[' + RED + 'ko' + ENDC + ']'
        pass


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
        host = raw_input('%-12s' % ('set hostname') + BLUE + ' > ' + ENDC)
        
    if (ssh == False) and (telnet == False):     
        service = raw_input('%-12s' % ('set service') + BLUE + ' > ' + ENDC)
        if service.lower() == 'ssh':
            ssh = True
        elif service.lower() == 'telnet':
            telnet = True
            
    if username == None:
        username = raw_input('%-12s' % ('set username') +BLUE + ' > ' + ENDC)
    if password == None:
        password = getpass.getpass('%-12s' % ('set password') + BLUE + ' > ' + ENDC)
        
    account = Account(username, password)
    
    if ssh:
        conn = SSH2()
    elif telnet:
        conn = Telnet()
    else:
        sys.exit(RED + '\n[!] Service options: (ssh|telnet)\n' + ENDC)
        
    conn.connect(host, port)
    conn.login(account)
    
    # Try to disable history for current shell session
    conn.execute('unset HISTFILE')
    
    # Print info about used Exscript driver
    driver = conn.get_driver()
    print BLUE + '\n[i] Using driver: ' + ENDC + driver.name
    
    logs = PATH_LOGS + '/' + host + '-' + str(int(time.time()))
    
    if plugin and (category == None):
        sys.exit(RED + '\n[!] No category\n' + ENDC)
    
    if category:
        print BLUE + '\n[i] Plugins category: ' + ENDC + category + '\n'
        if plugin:
            run_plugin(conn, logs, category, plugin)
        else:
            for p, plugin in enumerate(list_plugins(PATH_PLUGINS + '/' + category)):
                run_plugin(conn, logs, category, plugin)
     
    if (category == None) and (plugin == None):
        for c, category in enumerate(list_plugins(PATH_PLUGINS)):
            print BLUE + '\n[i] Loading plugins: ' + ENDC + category + '\n'
            for p, plugin in enumerate(list_plugins(PATH_PLUGINS + '/' + category)):
                run_plugin(conn, logs, category, plugin)

    conn.send('exit\r')
    conn.close()
        
    print BLUE + '\n[i] Logs saved in: ' + ENDC + PATH_LOGS + '\n'


if __name__ == "__main__":
    try:
        main()
    # Handle keyboard interrupts
    except KeyboardInterrupt:
        sys.exit(RED + '\n\n[!] Quitting...\n' + ENDC)
    # Handle exceptions
    except Exception, error:
        sys.exit(RED + '\n[!] Something went wrong. Quitting...\n' + ENDC)
