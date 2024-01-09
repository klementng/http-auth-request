import os
import secrets
import logging
import sys
import time
import argparse
import pidfile
import getpass
import pprint

import server.users.database
import server.users.object
import server.core.app
import server.core.helper
import server.config
import server.auth.modules

logger = logging.getLogger(__name__)

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Select mode')
    parser.add_argument('mode', type=str, help='Select modules', choices=[
                        "server", "users"])
    args = parser.parse_args(sys.argv[1:2])

    if args.mode == 'server':
        parser.add_argument("action", type=str,
                            help="Select actions", choices=["start", "kill"])
        args = parser.parse_args()

        if args.action == 'start':
            try:
                with pidfile.PIDFile("process.pid"):
                    logger.critical('Starting server!')
                    server.core.app.start()
            except pidfile.AlreadyRunningError:
                logger.critical('Server already running!')

        elif args.action == 'kill':
            try:
                with pidfile.PIDFile("process.pid"):
                    pass
            
            except pidfile.AlreadyRunningError:
                
                with open('process.pid') as f:
                    os.kill(int(f.read()),9)
                    logger.critical('Killed!')

    if args.mode == "users":
        parser.add_argument("action", type=str, help="Select actions", choices=[
                            "add", "delete", "edit"])
        parser.add_argument("username", type=str, nargs=1)

        parser.add_argument("--password", type=str, nargs=1)
        parser.add_argument("--roles", type=str)
        parser.add_argument(
            "--algo", type=str, help="hashing algorithm to be used", default='sha256')
        parser.add_argument("--salt_bytes", type=int,
                            help="number of salt bytes", default=16)
        parser.add_argument("--iterations", type=int, default=10000)

        args = parser.parse_args()
        
        modules:dict = server.core.app.auth_modules

        databases=[modules[k].local.db for k in modules.keys() if modules[k].local != None]

        unique_db = [databases[0]]

        for d in databases:
            for j in unique_db:
                if d.path != j.path:
                    unique_db.append(d)
        
        print("Choose a database to edit\n")
        print(
            "\n".join(
                [f"[{num}]:{value.path}" for num, value in enumerate(unique_db)]
            )
        )

        selected_db_i = -1
        while not (selected_db_i >=0 and selected_db_i < len(unique_db)):
            try:
                selected_db_i = int(input("\nSelect a database to edit: "))
            except ValueError:
                pass

        db: server.users.database.UserDatabase = unique_db[selected_db_i]
        
        if args.action == "add":
            if args.password == None:
                args.password = [getpass.getpass("Enter new password:")]
            
            if args.roles == None:
                user_roles_inputs = input("Enter the roles for the user separated by commas (default: ['default']): ")

                if user_roles_inputs == "":
                    args.roles = ['default']
                else:
                    args.roles = [s.strip() for s in user_roles_inputs.split(",")]

            new_user = server.users.object.User.create(
                args.username[0], 
                args.password[0],
                args.roles,
                algo=args.algo, 
                salt_n_bytes=args.salt_bytes, 
                iterations=args.iterations
            )

            if db.add_user(new_user):
                print(new_user)
                logger.info("Success")
            else:
                logger.warning("Failed! user with the same username already exists")

        elif args.action == "edit":
            
            action = input("Choose an attribute to edit: ['password','roles']")

            while not action in ['password','roles']:
                print("Invalid Option! ")
                action = input("Choose an attribute to edit (['password','roles']): ")
            
            current_user = db.get_user(args.username[0])

            if current_user == None:
                logger.critical("No such user found")
                exit(1)
            
            if action == 'password':
                if args.password == None:
                    args.password = [getpass.getpass("Enter new password:")]
                    current_user.change_password(args.password[0])
            else:
                user_roles_inputs = input(f"Enter all the roles separated by commas ({current_user.roles}): ")

                if user_roles_inputs == "":
                    current_user.roles = current_user.roles
                else:
                    current_user.roles = [s.strip() for s in user_roles_inputs.split(",")]

            if db.update_user(current_user):
                logger.info("success")
                print(current_user)
            else:
                logger.critical("Failed")

        elif args.action == 'delete':
            if db.delete_user(args.username[0]):
                logger.info("Success")
            else:
                logger.warning("Failed! username does not exist")
