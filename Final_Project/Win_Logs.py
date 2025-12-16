# --------------------------------- Win_logs.py -------------------------------------- #
# ------------------------------------------------------------------------------------ #
# --  Script för att läsa och filtrera windows säkerhetsloggar med hjälp av pywin32 -- #
# -----  Skickar även ett mail om "onormalt" beteende uppstår baserat på regler ------ #
# ------------------ Måste som köras administratör och kräver pywin32 ---------------- #
# ------------------------------------------------------------------------------------ # 
#  ------------------------## Skriven av Nicolas.H ##--------------------------------- #

            ## --Imports-- ##
from itertools import groupby
import win32evtlog
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import sys
from datetime import datetime




            ## --Variables--##
today_date = datetime.today().strftime('%Y-%m-%d %H:%M:%S')

            ## --Script Start Message-- ##
print("=" * 25 + "Windows Security Log Scanner" + "=" * 25)
with open("Logs.txt","a") as file:
    file.write(f"\n[{today_date}] Script was Initialized")

            ## --Menu Creation-- ##
while True:
    if sys.platform == "win32":
        menu_option = input("What would you like to do today? \n1. Perform Security log scan\n2. Help page\n3. Version\n4. Quit\n")
        with open("Logs.txt", "a") as file:
            file.write(f"\n[{today_date}] Menu Option written: {menu_option}")
        
            ## --Log Reading Settings-- ##
        if menu_option  == "1":
            try: 
                handle = win32evtlog.OpenEventLog(None, "Security")                                         # öpnnar securityloggen på den lokala datorn
                flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ           # sätta flagga för hur loggarna ska läsas
                sec_records = []
                
            except Exception as error:
                print(error)
                with open("Logs.txt","a") as file:
                    file.write(f"\n[{today_date}] {error}")                                                                            # skapa en lista för att lagra loggar
                sys.exit()

                ## --Email config-- ##
            def mail_func():    
                sender_email = ""
                receiver_mail = ""
                password = ""                                                                  
                message = MIMEMultipart()
                message["From"] = sender_email
                message["To"] = receiver_mail
                message["Subject"] = subject
                message.attach(MIMEText(body, "plain"))
                with smtplib.SMTP("smtp.gmail.com", 587) as server:
                    server.starttls()
                    server.login(sender_email, password)  
                    server.send_message(message)
            
            ##### --Main code-- ####
            while True:
                sec_logs = win32evtlog.ReadEventLog(handle, flags, 0)                               # läser loggarna från handle, hur den läser dem, och från vilken position
                if not sec_logs:                                                                    # Om det inte finns några logs kvar att läsa hoppa ur loopen
                    break                                                                           # 
                sec_records.extend(sec_logs)                                                        # lägger till de lästa loggarna i listan all_records

            evt_id = [sec_logs.EventID & 0xFFFF for sec_logs in sec_records]                        # Skapar en lista med endast event ID från alla loggar och grupperar dem baserat på ID
            for event,group in groupby(evt_id):                                                     # 
                try:
                    if event == 4625:                                                                   # Kollar om event ID är 4625 och räknar antalet misslyckade inloggningsförsök
                        fail_log = sum(1 for _ in group)                                                # 
                        if fail_log >= 5:                                                               # om misslyckade inloggningsförsök är större än 5 så skicka mail AKA alert
                            
                            ## --Create Email Content-- ##
                            subject = f" !! Event ID : {event} Multiple Failed logon attempts! *HIGH* !! "
                            body =  "Irregular activity has been detected investigate promptly!"
                            mail_func()
                            print(subject)
                            with open("Logs.txt", "a") as file:
                                file.write(f"\n[{today_date}] Event ID {event}: alert was triggered")

                    elif event == 1102:
                        fail_log = sum(1 for _ in group)
                        if fail_log >= 1:
                            
                            ## --Create Email Content-- ##
                            subject = f"Event ID : {event} Audit log has been cleared *HIGH*"
                            body =  "Irregular activity has been detected investigate promptly!"
                            mail_func()
                            print(subject)
                            with open() as file:
                                file.write(f"\n[{today_date}] Event ID {event}: alert was triggered")
        
                except Exception as error:
                    print(error)
                    with open("Logs.txt","a") as file:
                        file.write(f"\n[{today_date}] {error}")                                                                            # skapa en lista för att lagra loggar
                    sys.exit()
                       
            ## --Help Page-- ##
        elif menu_option == "2":
            try:
                print("=" * 25 + " Help page " + 25 * "=")
                with open("Help_Page.txt","r", encoding ="UTF-8") as file:
                    for line in file:
                        print(line.strip())
                print("=" * 25 + " Help page " + 25 * "=")
                with open("Logs.txt","a") as file:
                    file.write(f"\n[{today_date}] User accessed help page")
            except Exception as error:
                print(f"{error}")
                with open("Logs.txt","a") as file:
                    file.write(f"\n[{today_date}] {error}")
                sys.exit()
            
            # -- Version Page-- #
        elif menu_option == "3":
            print("=" * 25 + " Version 1.3.3.7 " + 25 * "=")
            with open("Logs.txt","a") as file:
                file.write(f"\n[{today_date}] User accesed script version")

            # --Exit Script-- #
        elif menu_option == "4":
            print("=" * 25 + " Goodbye! " + "=" * 25)
            with open("Logs.txt","a") as file:
                file.write(f"\n[{today_date}] User terminated script")
            break
            # --Incorrect input-- #
        else:
            print("=" * 25 + "You must choose one of the optiones 1, 2, 3 or 4 !" + 25 * "=")
            with open("Logs.txt","a") as file:
                file.write(f"\n[{today_date}] Incorrect menu choice")
            continue
            
            # --Incorrect OS-- #
    else:
        print("=" * 25 +"Operative system is not Windows" + 25 * "=")
        with open("Logs.txt","a") as file:
                file.write(f"\n[{today_date}] Script was run on a {sys.platform} system")
        break
        



                
            
            

                

