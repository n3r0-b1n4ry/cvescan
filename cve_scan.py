from shodan import Shodan
from threading import Thread, activeCount
from time import sleep
from datetime import datetime
from cvesearchapi import CVESearch
import os, sys, argparse

intro_text = "\033[1;95m\n  ______     _______ ____   {}\n / ___\ \   / / ____/ ___|  ___ __ _ _ __\n| |    \ \ / /|  _| \___ \ / __/ _` | '_ \ \n| |___  \ V / | |___ ___) | (_| (_| | | | |\n \____|  \_/  |_____|____/ \___\__,_|_| |_|\n\033[0;m".format('v0.1#dev')
print(intro_text)

flag = False

parser = argparse.ArgumentParser(usage='python {} [options]'.format(__file__))
parser.add_argument('-i', metavar='IP', type=str, help='IP address. e.g 132.43.34.12')
parser.add_argument('--ip-list', type=str, help='Filename contains the ip list')
parser.add_argument('-o', metavar='OUTPUT_PATH', type=str, help='Local path to store result. Default storing in folder dump')
args = parser.parse_args()

def printInfo(message):
        print('[\033[1;94m{}\033[0;m]: {}'.format(getTime(), message))

def printError(message):
        print('[\033[1;94m{}\033[0;m]: \033[1;91m{}\033[0;m'.format(getTime(), message))

def printComplete(message):
        print('[\033[1;94m{}\033[0;m]: \033[1;92m{}\033[0;m'.format(getTime(), message))

def getTime():
        now = datetime.now()
        return now.strftime('%H:%M:%S')

def exit(message = None):
        try:
                if message is not None:
                        printError(message)
                if activeCount() > 1:
                        printError('!!!Killing all threads!!!')
                        while activeCount() > 1:
                                sleep(0.001)
                if flag is True:
                        printInfo('All results have been dump in {}'.format(dumppath))
                printError('Exiting script!!!')
                sys.exit()
        except KeyboardInterrupt:
                pass

def search(ip):
        try:
                s = api.host(ip)

                if len(s['vulns']) > 0:
                        flag = True
                        printComplete('{} have vulnebilities'.format(ip))
                        fo = open('{}{}.csv'.format(dumppath,ip),'w',newline='')
                        fo.write('{};{}'.format('CVE-ID', 'Summary'))
                        fo.write('\n')
                        for vuln in s['vulns']:
                                fo.write('{};{}'.format(vuln, cve.id(vuln)['summary']))
                                fo.write('\n')
                else:
                        exit(e)

        except KeyboardInterrupt:
                exit("User aborted!")
        except Exception as e:
                printError('{} does not have vulnebilities'.format(ip))

def main():
        try:
                global dumppath
                global api
                global cve
                currentpath = os.path.dirname(os.path.abspath(__file__))
                if os.path.isfile(currentpath + "/api.key") is True:
                        api_key = str(open("api.key","r").read())
                        if api_key is not '':
                                api = Shodan(api_key)
                        else:
                                exit("Please insert Shodan API key into filename api.key")
                        cve = CVESearch()
                else:
                        exit("api.key is not exist. Please create filename api.key with Shodan API key!")
                        
                if args.o is None:
                        if os.path.isdir(currentpath + "/dump") is not True:
                                os.mkdir(currentpath + "/dump")
                                print(currentpath + "/dump", "is created")
                        dumppath = currentpath + "/dump/"
                else:
                        if os.path.isdir(args.o) is True:
                                dumppath = args.o
                                if (dumppath[len(dumppath) - 1] is not '/') or (dumppath[len(dumppath) - 1] is not "\\"):
                                        dumppath += "/"
                        else:
                                exit('Your output path is invalid or not exist. Please try again!')

                if (args.i == None) and (args.ip_list == None):
                        exit('You need to insert mandatory option. Use -h to show help')
                elif  (args.i is not None) and (args.ip_list is not None):
                        exit('You must be use only 1 option. --ip or --ip-list, not a both.')
                elif args.i is not None:
                        search(ip)
                        exit('Scan ended!')
                elif args.ip_list is not None:
                        filename = args.ip_list
                        fi = open(filename, "r")
                        iplist = fi.read().split("\n")

                        for ip in iplist:
                                th = Thread(target=search, args=(ip,))
                                th.daemon = True
                                th.start()
                                while activeCount() > 5:
                                        sleep(0.001)
                        
                        while activeCount() > 1:
                                sleep(0.001)
                        exit('Scan ended!')

        except Exception as e:
                exit(e)


if __name__ == '__main__':
        try:
                main()
        except KeyboardInterrupt:
                exit("User aborted!")