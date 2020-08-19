from shodan import Shodan
from threading import Thread, activeCount
from time import sleep
from datetime import datetime
from cvesearchapi import CVESearch, Texttable
import os, sys, argparse

intro_text = "\033[1;95m\n  ______     _______ ____   {}\n / ___\ \   / / ____/ ___|  ___ __ _ _ __\n| |    \ \ / /|  _| \___ \ / __/ _` | '_ \ \n| |___  \ V / | |___ ___) | (_| (_| | | | |\n \____|  \_/  |_____|____/ \___\__,_|_| |_|\n\033[0;m".format('v0.1#dev')
print(intro_text)

parser = argparse.ArgumentParser(usage='python {} [options]'.format(__file__))
parser.add_argument('-i', metavar='IP', type=str, help='IP address. e.g 132.43.34.12')
parser.add_argument('--ip-list', metavar='FILENAME', type=str, help='Filename contains the ip list')
parser.add_argument('--outpath', metavar='OUTPUT_PATH', type=str, help='Local path to store results')
parser.add_argument('--dump', nargs='?', default=None, const=True, help='Dump results to file. Default store in folder dump, or you can use --outpath to store different path')
args = parser.parse_args()

def printInfo(message):
        print('[\033[1;94m{}\033[0;m]: {}'.format(getTime(), message))

def printError(message):
        print('[\033[1;94m{}\033[0;m]: \033[1;91m{}\033[0;m'.format(getTime(), message))

def printComplete(message):
        print('[\033[1;94m{}\033[0;m]: \033[1;92m{}\033[0;m'.format(getTime(), message))

def dumpCSV(ip,content):
        fo = open('{}{}.csv'.format(dumppath,ip),'w',newline='')
        for data in content:
                fo.write('"{}";"{}";"{}";\n'.format(data[0],data[1],data[2]))
        fo.close()

def getTime():
        now = datetime.now()
        return now.strftime('%H:%M:%S')

def exit(message = None):
        try:
                if message != None:
                        printError(message)
                if activeCount() > 1:
                        printError('!!!Killing all threads!!!')
                        while activeCount() > 1:
                                sleep(0.001)
                if args.dump == True:
                        printInfo('All results have been dump in {}'.format(dumppath))
                printError('Exiting script!!!')
                sys.exit()
        except KeyboardInterrupt:
                pass

def search(ip,vuln):
        try:
                json_cveid = cve.id(vuln)
                capec_name = ''
                cvss = 'Unknown'
                if len(json_cveid['capec']) != 0:
                        for capec in json_cveid['capec']:
                                capec_name += '\n' + capec['name']
                        capec_name = capec_name.replace('\n','',1)
                else:
                        capec_name = 'Unknown'
                if 'cvss' in json_cveid:
                        cvss = cve.id(vuln)['cvss']
                cveid = [vuln,capec_name,cvss]
                tables[ip].append(cveid)

        except KeyboardInterrupt:
                exit("User aborted!")
        except Exception as e:
                exit(e)

def scan(ip):
        try:
                s = api.host(ip)

                if 'vulns' in s:
                        printComplete('{} have vulnebilities'.format(ip))
                        tables[ip] = [['CVE-ID','CAPEC Name','CVSS Base']]
                        for vuln in s['vulns']:
                                if 'CVE' in vuln:
                                        th1 = Thread(target=search, args=(ip,vuln))
                                        th1.daemon = True
                                        th1.start()
                                        while activeCount() > 5:
                                                sleep(0.001)
                        
                        if args.dump == True:
                                dumpCSV(ip, tables[ip])

                else:
                        exit('{} does not have vulnebilities'.format(ip))

        except KeyboardInterrupt:
                exit("User aborted!")
        except KeyError:
                exit('{} does not have vulnebilities'.format(ip))
        except Exception as e:
                exit(e)

def main():
        try:
                global dumppath
                global api
                global cve
                global tables
                tables = {}
                currentpath = os.path.dirname(os.path.abspath(__file__))
                if os.path.isfile(currentpath + "/api.key") == True:
                        api_key = open("api.key","r").read().splitlines()[0]
                        if api_key != '':
                                api = Shodan(api_key)
                        else:
                                exit("Please insert Shodan API key into filename api.key")
                        cve = CVESearch()
                else:
                        exit("api.key != exist. Please create filename api.key with Shodan API key!")
                        
                if args.outpath == None:
                        if os.path.isdir(currentpath + "/dump") != True:
                                os.mkdir(currentpath + "/dump")
                                print(currentpath + "/dump", "is created")
                        dumppath = currentpath + "/dump/"
                else:
                        if os.path.isdir(args.outpath) == True:
                                dumppath = args.outpath
                                if (dumppath[len(dumppath) - 1] != '/') or (dumppath[len(dumppath) - 1] != "\\"):
                                        dumppath += "/"
                        else:
                                exit('Your output path is invalid or not exist. Please try again!')

                if (args.i == None) and (args.ip_list == None):
                        exit('You need to insert mandatory option. Use -h to show help')
                elif  (args.i != None) and (args.ip_list != None):
                        exit('You must be use only 1 option. -i or --ip-list, not a both.')
                elif args.i != None:
                        scan(args.i)
                        while activeCount() > 1:
                                sleep(0.001)

                        if args.dump == None:
                                for ip in tables:
                                        print("Host {}:".format(ip))
                                        output = Texttable()
                                        output.set_cols_dtype(["t","t","t"])
                                        output.set_cols_align(["c","l","c"])
                                        output.set_cols_valign(["m","m","m"])
                                        output.add_rows(tables[ip])
                                        print(output.draw(),"\n\n")
                        
                        exit('Scan ended!')
                elif args.ip_list != None:
                        filename = args.ip_list
                        fi = open(filename, "r")
                        iplist = fi.read().split("\n")

                        for ip in iplist:
                                th = Thread(target=scan, args=(ip,))
                                th.daemon = True
                                th.start()
                                while activeCount() > 5:
                                        sleep(0.001)
                        
                        while activeCount() > 1:
                                sleep(0.001)

                        if args.dump == None:
                                for ip in tables:
                                        print("Host {}:".format(ip))
                                        output = Texttable()
                                        output.set_cols_dtype(["t","t","t"])
                                        output.set_cols_align(["c","c","c"])
                                        output.set_cols_valign(["m","m","m"])
                                        output.add_rows(tables[ip])
                                        print(output.draw(),"\n\n")

                        exit('Scan ended!')

        except Exception as e:
                exit(e)


if __name__ == '__main__':
        try:
                main()
        except KeyboardInterrupt:
                exit("User aborted!")