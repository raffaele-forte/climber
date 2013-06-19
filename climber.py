#!/usr/bin/env python

import argparse, getpass, os, sys, time

from Exscript.util.template import eval_file
from Exscript.protocols import SSH2, Telnet, Account

# Editable paths
PATH_LOGS    = '~/climber'
PATH_PLUGINS = 'plugins'

# Terminal colors
INFO  = '\033[97m'
DONE  = '\033[92m'
ERROR = '\033[91m'
ENDC  = '\033[0m'

DEVNULL = open(os.devnull, 'w')


def print_banner():
    header  = INFO + '   _________  ___  __       ____                   \n' + ENDC
    header += INFO + '   \_   ___ \|  | |__| _____\_ |__   ___________   \n' + ENDC
    header += INFO + '   /    \  \/|  | |  |/     \| __ \_/ __ \_  __ \  \n' + ENDC
    header += INFO + '   \     \___|  |_|  |  Y Y  \ \_\ \  ___/|  | \/  \n' + ENDC
    header += INFO + '    \______  /____/__|__|_|  /___  /\___  >__|     \n' + ENDC
    header += INFO + '           \/              \/    \/     \/         \n' + ENDC
    header += INFO + '    Checks Unix system for privilege escalations   \n' + ENDC
    print header


def myparser():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Auditing tool to check system misconfigurations that may allow attackers to escalate privileges.', version='Climber v.0.2')
   
    group = parser.add_argument_group('connection')
    group.add_argument('-H', '--host', action="store")
    group.add_argument('-P', '--port', type=int)
    group.add_argument('--ssh', action='store_true', help='use ssh connection')
    group.add_argument('--telnet', action='store_true', help='use telnet connection')
    
    group = parser.add_argument_group('authentication')
    group.add_argument('--username', action="store")
    group.add_argument('--password', action="store")
    
    #group = parser.add_argument_group('plugins')
    #group.add_argument('--category', action='store')
    #group.add_argument('--plugin', action='store')
        
    return parser.parse_args()
    

def save_logs(text, path, filename):
 
    logs_dir = os.path.expanduser(path)
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    
    # Write mode creates a new file or overwrites the existing content of the file.
    try:
        f = open(logs_dir + '/' + filename, 'w')
        try:
            # Write a sequence of strings to a file
            f.writelines(text)
        finally:
            f.close()
    except Exception, e:
        sys.exit(ERROR + '\n[!] ' + str(e) + '\n' + ENDC)
        

def list_plugins(directory):
    try:
        plugins = os.listdir(directory)
        plugins.sort()
        return plugins
    except Exception, e:
        sys.exit(ERROR + '\n[!] ' + str(e) + '\n' + ENDC)
        

def run_plugin(conn, directory, category, plugin):
    
    path = directory + '/' + category
    
    try:
        eval_file(conn, PATH_PLUGINS + '/' + category + '/' + plugin, foobar = None)      
        save_logs(conn.response, path, plugin + '.log')        
        print '  %-20s' % (plugin) + '[' + DONE + 'ok' + ENDC + ']'       
    except:
        print '  %-20s' % (plugin) + '[' + ERROR + 'ko' + ENDC + ']'


def main():
 
    args = myparser()
    print_banner() 
    
    host     = args.host
    port     = args.port 
    username = args.username
    password = args.password
    ssh      = args.ssh
    telnet   = args.telnet
    #category = args.category
    #plugin   = args.plugin     

    if username == None:
        username = raw_input('\nEnter username ' + INFO + '> ' + ENDC)
    if password == None:
        password = getpass.getpass('Enter password ' + INFO + '> ' + ENDC)
        
    account = Account(username, password)
    
    if ssh:
        conn = SSH2()
    elif telnet :
        conn = Telnet()
    else:
        sys.exit(ERROR + '\n[!] Set the connection type: (--ssh|--telnet)\n' + ENDC)
        
    conn.connect(host, port)
    conn.login(account)
    
    # Print info about used Exscript driver
    driver = conn.get_driver()
    print INFO + '\n[i] Using driver: ' + ENDC + driver.name
    
    logs_dir = PATH_LOGS + '/' + host + '-' + str(int(time.time()))           
     
    for num, category in enumerate(list_plugins(PATH_PLUGINS)):
        print INFO + '\n[i] Loading plugins: ' + ENDC + category +'\n'
        for num, plugin in enumerate(list_plugins(PATH_PLUGINS + '/' + category)):
            run_plugin(conn, logs_dir, category, plugin)

    conn.send('exit\r')
    conn.close()
        
    print INFO + '\n[i] Logs saved!\n' + ENDC

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt, e:
        sys.exit(ERROR + '\n\n[!] Quitting...\n' + ENDC)
