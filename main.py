import os
import logging
import sys
import time
import argparse
import pidfile
import getpass



os.environ["CONFIG_DIR"] =  os.getenv("CONFIG_DIR","/config")
os.environ["SETTINGS_PATH"] = os.getenv("SETTINGS_PATH",os.path.join(os.environ["CONFIG_DIR"] ,'settings.yml'))

os.environ["LOG_LEVEL"] = os.getenv("LOG_LEVEL","DEBUG")

logging.basicConfig(format='%(asctime)s - %(name)s - %(funcName)s() - %(levelname)s - %(message)s',level=logging.INFO)

import server.core
import server.users

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='Select mode')
    parser.add_argument('mode', type=str,help='Select modules', choices=["server","users"])
    args = parser.parse_args(sys.argv[1:2])

    if args.mode == 'server':
        parser.add_argument("action",type=str,help="Select actions",choices=["start","kill"])
        args = parser.parse_args()

        if args.action == 'start':
                try:
                    with pidfile.PIDFile("pidfile"):
                        server.core.start()
                except pidfile.AlreadyRunningError:
                    print('Server already running!')

        elif args.action == 'kill':
            try:
                os.kill(int(open('pidfile').read()), 2)
                print("Sent SIGKILL")
                time.sleep(3)

                os.kill(int(open('pidfile').read()), 0)
                print("Not Killed")

            except OSError:
                print("Killed!")
        

    if args.mode == "users":
        parser.add_argument("action",type=str,help="Select actions",choices=["add","delete","edit"])
        parser.add_argument("username",type=str,nargs=1)

        parser.add_argument("--password",type=str,nargs=1)
        parser.add_argument("--algo",type=str,help="hashing algorithm to be used",default='sha256')
        parser.add_argument("--salt_bytes",type=int,help="number of salt bytes",default=16)
        parser.add_argument("--iterations",type=int,default=10000)

        args = parser.parse_args()
        if args.action == "add":
            if args.password == None:
                args.password = [getpass.getpass("Enter new password:")]
            
            status, msg = server.users.add_user(args.username[0],args.password[0],algo=args.algo,salt_bytes=args.salt_bytes,iterations=args.iterations)
            print(msg)

        elif args.action == "edit":
            if args.password == None:
                args.password = [getpass.getpass("Enter new password:")]
            
            status, msg = server.users.edit_user(args.username[0],args.password[0],algo=args.algo,salt_bytes=args.salt_bytes,iterations=args.iterations)
            print(msg)
        
        elif args.action == 'delete':
            status, msg = server.users.delete_user(args.username[0],verify=False)
            print(msg)
            