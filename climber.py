#!/usr/bin/env python

# Copyright(c) 2011-2013 Raffaele Forte <raffaele.forte@gmail.com>
# http://www.backbox.org/
#
# This file is part of BackBox Scripts
#
# backbox-scripts is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as 
# published by the Free Software Foundation, either version 3 of the 
# License, or (at your option) any later version.
#
# backbox-scripts is distributed in the hope that it will be 
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with backbox-scripts. If not, see <http://www.gnu.org/licenses/>.

import argparse, getpass, os, sys, time

from Exscript.util.interact import read_login
from Exscript.util.template import eval_file
from Exscript.protocols import SSH2, Telnet, Account

INFO  = '\033[97m'
DONE  = '\033[92m'
ERROR = '\033[91m'
ENDC  = '\033[0m'

DEVNULL = open(os.devnull, 'w')

PATH = "~/climber-logs/"


def print_banner():
    header  = INFO +'   _________  ___  __       ____                  \n' + ENDC
    header += INFO +'   \_   ___ \|  | |__| _____\_ |__   ___________  \n' + ENDC
    header += INFO +'   /    \  \/|  | |  |/     \| __ \_/ __ \_  __ \ \n' + ENDC
    header += INFO +'   \     \___|  |_|  |  Y Y  \ \_\ \  ___/|  | \/ \n' + ENDC
    header += INFO +'    \______  /____/__|__|_|  /___  /\___  >__|    \n' + ENDC
    header += INFO +'           \/              \/    \/     \/        \n' + ENDC
    print header
    

def make_dirs(host):
    my_dir = os.path.expanduser(PATH + host + '-' + str(int(time.time())))
    if not os.path.exists(my_dir):
        os.makedirs(my_dir)
    return my_dir


def save_log(text, filename):
    # Write mode creates a new file or overwrites the existing content of the file.
    try:
        f = open(filename, 'w')
        try:
            # Write a sequence of strings to a file
            f.writelines(text)
        finally:
            f.close()
    except Exception, e:
        sys.exit(ERROR + '\n[!] ' + str(e) + '\n'+ ENDC)
        
        
def plugins():
    try:
        plugins = os.listdir('plugins/')
        plugins.sort()
        return plugins
    except Exception, e:
        sys.exit(ERROR + '\n[!] ' + str(e) + '\n'+ ENDC)


def do_something(host, port, service, username, password, plugin):
    
    try:
        
        if username == None:
            username = raw_input('\nEnter username ' + INFO + '> ' + ENDC)
        
        if password == None:
            password = getpass.getpass('Enter password ' + INFO + '> ' + ENDC)
        
        account = Account(username, password)

        if service == 'ssh':
            conn = SSH2()
        if service == 'telnet':
            conn = Telnet()

        conn.connect(host, port)
        conn.login(account)
        
        if conn.guess_os() != 'shell':
            sys.exit('[!] Not Unix shell')
            
        my_dir = make_dirs(host)
     
        if plugin:
            print INFO + '\n[i] Loading plugin...\n' + ENDC
            
            try:
                eval_file(conn, 'plugins/' + plugin , foobar = None)
                save_log(conn.response, my_dir + '/' + plugin + '.log')         
                print '  %2i)\t %-20s' % (1, plugin) + '[' + DONE + 'ok' + ENDC + ']'           
            except:
                print '  %2i)\t %-20s' % (1, plugin) + '[' + ERROR + 'ko' + ENDC + ']'
        else:
            print INFO + '\n[i] Loading ' + str(len(plugins())) + ' plugins...\n' + ENDC
            
            for num, plugin in enumerate(plugins()):
                try:
                    eval_file(conn, 'plugins/' + plugin , foobar = None)
                    save_log(conn.response, my_dir + '/' + plugin + '.log')         
                    print '  %2i)\t %-20s' % (num+1, plugin) + '[' + DONE + 'ok' + ENDC + ']'           
                except:
                    print '  %2i)\t %-20s' % (num+1, plugin) + '[' + ERROR + 'ko' + ENDC + ']'
        
        conn.send('exit\r')
        conn.close()
        
        print INFO + '\n[i] Log saved!\n' + ENDC
    
    except Exception, e:
        sys.exit(ERROR + '\n[!] ' + str(e) + '\n'+ ENDC)


def main():
    
    print_banner()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Auditing tool to check local system misconfigurations that may allow attackers to escalate privileges.', version='%(prog)s v.0.1')
   
    group = parser.add_argument_group('connection')
    group.add_argument('-H', '--host', action="store")
    group.add_argument('-P', '--port', type=int)
    group.add_argument('--ssh', action='store_true', help='use ssh connection')
    group.add_argument('--telnet', action='store_true', help='use telnet connection')
    
    group = parser.add_argument_group('authentication')
    group.add_argument('--username', action="store")
    group.add_argument('--password', action="store")
    
    group = parser.add_argument_group('plugins')
    group.add_argument('-L', '--list', action='store_true')
    group.add_argument('--plugin', action='store')
        
    args = parser.parse_args()
    
    host = args.host
    port = args.port
    
    username = args.username
    password = args.password
    
    plugin = args.plugin
    
    service = None

    if args.ssh :
        service = 'ssh'
    if args.telnet :
        service = 'telnet'
        
    if args.list:
        print INFO + '\n[i] Plugin list...\n' + ENDC
        for num, plugin in enumerate(plugins()):
            print '  %i)\t %s' % (num+1, plugin)
        print INFO + '\n[!] Done!\n' + ENDC        
        sys.exit()
        
    if service != None:
        # Connect to remote host
        do_something(host, port, service, username, password, plugin)
    else:
        sys.exit(ERROR + '\n[!] Set the connection type: (--ssh|--telnet)\n'+ ENDC)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt, e:
        sys.exit(ERROR + '\n\n[!] Quitting...\n' + ENDC)
