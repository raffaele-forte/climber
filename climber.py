#!/usr/bin/env python

from Exscript.protocols import SSH2, Telnet, Account
from Exscript.util.template import eval_file
from distutils import dir_util
from mako.template import Template
from os.path import expanduser
import argparse
import cgi
import getpass
import os
import sys
import time

# Customizable paths
INSTALL_PATH = os.path.dirname(__file__)
LOGS_PATH = expanduser('~') + '/climber'

# Terminal colors
BLUE = '\033[34m'
GREEN = '\033[32m'
RED = '\033[31m'
ENDC = '\033[0m'

DEVNULL = open(os.devnull, 'w')


def print_banner():
    header = BLUE + '   _________  ___  __       ____                   \n' + ENDC
    header += BLUE + '   \_   ___ \|  | |__| _____\_ |__   ___________   \n' + ENDC
    header += BLUE + '   /    \  \/|  | |  |/     \| __ \_/ __ \_  __ \  \n' + ENDC
    header += BLUE + '   \     \___|  |_|  |  Y Y  \ \_\ \  ___/|  | \/  \n' + ENDC
    header += BLUE + '    \______  /____/__|__|_|  /___  /\___  >__|     \n' + ENDC
    header += BLUE + '           \/              \/    \/     \/         \n' + ENDC
    header += ' Check UNIX/Linux systems for privilege escalation \n' 
    header += BLUE + ' ------------------------------------------------- \n' + ENDC
    print header

def args_parser():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Automated auditing tool to check UNIX/Linux systems misconfigurations which may allow local privilege escalation', version='Climber v.1.1 - Copyleft Raffaele Forte')
   
    group = parser.add_argument_group('connection')
    group.add_argument('--host', action='store', help='set hostname or ip')
    group.add_argument('--port', type=int, help='set port number')
    group.add_argument('--ssh', action='store_true', help='set ssh connection')
    group.add_argument('--telnet', action='store_true', help='set telnet connection')
    
    group = parser.add_argument_group('authentication')
    group.add_argument('--username', action='store', help='set username')
    group.add_argument('--password', action='store', help='set password')
    
    group = parser.add_argument_group('plugins')
    group.add_argument('--category', action='store', help='set category')
    group.add_argument('--plugin', action='store', help='set plugin')
        
    return parser.parse_args()


def html_report(dictionary, path):
  
    html_text = ''
    
    html_template = Template(filename=INSTALL_PATH + '/templates/report.txt')
    
    for category in sorted(dictionary.keys()):
        
        dict_tmp = {}
        dict_tmp = dictionary[category]
        
        html_text += '        <h2>' + category + '</h2>\n\n'

        for plugin in sorted(dict_tmp.keys()):
            
            html_text += '        <!-- collapsible -->\n'
            html_text += '        <div class="page_collapsible" id="body-section-' + plugin + '">' + plugin + '<span></span></div>\n'
            html_text += '        <div class="container">\n'
            html_text += '            <div class="content">\n'
            html_text += '                <pre><code>' + cgi.escape(dict_tmp[plugin]) + '</code></pre>\n'
            html_text += '            </div>\n'
            html_text += '        </div>\n'
            html_text += '        <!-- end collapsible -->\n\n'
        
    html = html_template.render(html_block=html_text.decode('utf-8'))

    # Make directories
    logs_path = os.path.expanduser(path)
    if not os.path.exists(logs_path):
        os.makedirs(logs_path)
        
    dir_util.copy_tree(INSTALL_PATH + '/html', logs_path)

    report_file = open(logs_path + '/index.html', 'w')
    report_file.write(html.encode('utf-8'))
    report_file.close()


def main():
 
    args = args_parser()
    print_banner()
    
    host = args.host
    port = args.port 
    username = args.username
    password = args.password
    ssh = args.ssh
    telnet = args.telnet
    category = args.category
    plugin = args.plugin
    
    if plugin and (category == None):
        sys.exit(RED + '\n[!] No category\n' + ENDC)
    
    # Set host
    if host == None:
        host = raw_input('set host' + BLUE + ' > ' + ENDC)
    
    # Set service
    if (ssh == False) and (telnet == False):     
        service = raw_input('set service [ssh|telnet]' + BLUE + ' > ' + ENDC)
        if service.lower() == 'ssh':
            ssh = True
        elif service.lower() == 'telnet':
            telnet = True
    if ssh:
        conn = SSH2()
    elif telnet:
        conn = Telnet()
    else:
        sys.exit(RED + '\n[!] Bad service type. Options: [ssh|telnet]\n' + ENDC)
        
    # Set username
    if username == None:
        username = raw_input('set username' + BLUE + ' > ' + ENDC)
        
    # Set password  
    if password == None:
        password = getpass.getpass('set password' + BLUE + ' > ' + ENDC)
        
    # Create account
    account = Account(username, password)

    # Connect and login
    conn.connect(host, port)
    conn.login(account)
    
    # Try to disable history for current shell session
    conn.execute('unset HISTFILE')
    
    # Print info about used Exscript driver
    driver = conn.get_driver()
    print BLUE + '\n[i] Using driver: ' + ENDC + driver.name
    
    # Set logs directory
    logs_path = LOGS_PATH + '/' + host + '-' + str(int(time.time()))
    
    if category:
        print BLUE + '\n[i] Plugins category: ' + ENDC + category + '\n'
        dict_categories = {}
        dict_plugins = {}
        
        # Run single plugin
        if plugin:
            try:
                eval_file(conn, INSTALL_PATH + '/plugins/' + category + '/' + plugin)             
                dict_plugins[plugin] = conn.response
 
                print '  %-20s' % (plugin) + '[' + GREEN + 'ok' + ENDC + ']'       
            except:
                print '  %-20s' % (plugin) + '[' + RED + 'ko' + ENDC + ']'
                pass
            
            dict_categories[category] = dict_plugins
            
        # Run plugins by single category
        else:
            for plugin in sorted(os.listdir(INSTALL_PATH + '/plugins/' + category)):
                try:
                    eval_file(conn, INSTALL_PATH + '/plugins/' + category + '/' + plugin)              
                    dict_plugins[plugin] = conn.response
                    
                    print '  %-20s' % (plugin) + '[' + GREEN + 'ok' + ENDC + ']'       
                except:
                    print '  %-20s' % (plugin) + '[' + RED + 'ko' + ENDC + ']'
                    pass
                
            dict_categories[category] = dict_plugins
            
    # Run all plugins by category
    if (category == None) and (plugin == None):
        dict_categories = {}
        
        for category in sorted(os.listdir(INSTALL_PATH + '/plugins')):
            print BLUE + '\n[i] Plugins category: ' + ENDC + category + '\n'
            dict_plugins = {}
            
            for plugin in sorted(os.listdir(INSTALL_PATH + '/plugins/' + category)):
                try:
                    eval_file(conn, INSTALL_PATH + '/plugins/' + category + '/' + plugin)       
                    dict_plugins[plugin] = conn.response
                    
                    print '  %-20s' % (plugin) + '[' + GREEN + 'ok' + ENDC + ']'       
                except:
                    print '  %-20s' % (plugin) + '[' + RED + 'ko' + ENDC + ']'
                    pass
                
            dict_categories[category] = dict_plugins
    
    # Exit and close remote connection
    conn.send('exit\r')
    conn.close()
    
    # Generate report
    html_report(dict_categories, logs_path)     
    print BLUE + '\n[i] Report saved to: ' + ENDC + logs_path + '/index.html\n'


if __name__ == '__main__':
    try:
        main()
    # Handle keyboard interrupts
    except KeyboardInterrupt:
        sys.exit(RED + '\n\n[!] Quitting...\n' + ENDC)
    # Handle exceptions
    except Exception, error:
        sys.exit(RED + '\n[!] ' + str(error) + '\n' + ENDC)
