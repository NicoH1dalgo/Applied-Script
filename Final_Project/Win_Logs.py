# ==================================================================================== #
# --------------------------------- Win_logs.py -------------------------------------- #
# ------------------------------------------------------------------------------------ #
# --  Script för att läsa och filtrera windows säkerhetsloggar med hjälp av pywin32 -- #
# -----  Skickar även ett mail om "onormalt" beteende uppstår baserat på regler ------ #
# ------------------ Måste som köras administratör och kräver pywin32 ---------------- #
# ------------------------------------------------------------------------------------ # 
#  ------------------------## Skriven av Nicolas.H ##--------------------------------- #
# ==================================================================================== #
          
         
            # ------------- Imports ---------------- #

from itertools import groupby
import win32evtlog
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import sys
from datetime import datetime




            # -------- Variable/Functions ---------- #
today_date = datetime.today().strftime('%Y-%m-%d %H:%M:%S')

            ## --Email config-- ##
def mail_func():                                                                                            
    sender_email = "mailscriptcs25@gmail.com"                                                                                       # Hårdkodad avsändar email adress 
    receiver_mail = "mailscriptcs25@gmail.com"                                                                                      # Hårdkodad mottagar email adress
    password = "kbiu mlza jykt jdub"                                                                                           # Hårdkodad app-lösenord för avsändar email adress      
    message = MIMEMultipart()                                                                               #                                    
    message["From"] = sender_email                                                                          # sätter avsändare mail setting i headern                                      
    message["To"] = receiver_mail                                                                           # sätter Motager mail setting i headern                         
    message["Subject"] = subject                                                                            # sätter Subject mail setting i headern                    
    message.attach(MIMEText(body, "plain"))                                                                 # Attachar body texten till mailet                 
    with smtplib.SMTP("smtp.gmail.com", 587) as server:                                                     # Sätter upp SMTP server inställningar för gmail                      
        server.starttls()                                                                                   # Kör TLS för säker anslutning                  
        server.login(sender_email, password)                                                                # Loggar in på avsändar email adressen              
        server.send_message(message)                                                                        # Skickar mailet till mottagaren             



def error_log():                                                                                            #
    print(error)                                                                                            # Skriver ut error meddelandet i console                                    
    with open("Logs.txt","a") as file:                                                                      # Öppnar loggfilen i append läge   
        file.write(f"\n[{today_date}] {error}")                                                             # Loggar error meddelandet i loggfilen             
    sys.exit() 


            # ------- Script Start Message --------- #
print("=" * 25 + "Windows Security Log Scanner" + "=" * 25)
with open("Logs.txt","a") as file:
    file.write(f"\n[{today_date}] Script was Initialized")

            # ---------- Menu Creation ------------- #
while True:
    if sys.platform == "win32":                                                                             # Kollar om OS är Windows
        menu_option = input("What would you like to do today? \n1. Perform Security log scan\n2. Help page\n3. Version\n4. Quit\n") #   Tar in användarens menyval
        with open("Logs.txt", "a") as file:                                                                 # Öppnar loggfilen i append läge                                    
            file.write(f"\n[{today_date}] Menu Option written: {menu_option}")                              # Loggar användarens menyval i loggfilen               
        
            # ---- Security Log Reading Settings ---- #
        if menu_option  == "1":
            try: 
                handle = win32evtlog.OpenEventLog(None, "Security")                                         # öpnnar securityloggen på den lokala datorn
                flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ           # sätta flagga för hur loggarna ska läsas
                sec_records = []                                                                            # skapa en lista för att lagra loggar                       
                
            except Exception as error:
                error_log()                                                 
            
            # ======================================== #
            # ------------ Main code ----------------- #
            # ======================================== #
            while True:
                sec_logs = win32evtlog.ReadEventLog(handle, flags, 0)                                       # läser loggarna från handle, hur den läser dem, och från vilken position
                if not sec_logs:                                                                            # Om det inte finns några logs kvar att läsa hoppa ur loopen
                    break                                                                                   # 
                sec_records.extend(sec_logs)                                                                # lägger till de lästa loggarna i listan all_records

            evt_id = [sec_logs.EventID & 0xFFFF for sec_logs in sec_records]                                # Skapar en lista med endast event ID från alla loggar och grupperar dem baserat på ID
            for event,group in groupby(evt_id):                                                             # 
                try:
                    if event == 4625:                                                                       # Kollar om event ID är 4625 och räknar antalet misslyckade inloggningsförsök
                        fail_log = sum(1 for _ in group)                                                    # 
                        if fail_log >= 5:                                                                   # om misslyckade inloggningsförsök är större än 5 så skicka mail AKA alert
                            
                            # ------- Create Email Content --------- #
                            subject = f" !! Event ID : {event} Multiple Failed logon attempts! *HIGH* !! "  # Sätter ämnet för mailet
                            body =  "Irregular activity has been detected investigate promptly!"            # Sätter body för mailet
                            mail_func()                                                                     # Kör mail funktionen                           
                            print(subject)                                                                  # Skriver ut ämnet i console          
                            with open("Logs.txt", "a") as file:                                             # Loggar händelsen i loggfilen     
                                file.write(f"\n[{today_date}] Event ID {event}: alert was triggered")       # Dagens datum och tid + event ID + alert meddelande i loggen

                    elif event == 1102:
                        fail_log = sum(1 for _ in group)
                        if fail_log >= 1:
                            subject = f"Event ID : {event} Audit log has been cleared *HIGH*"
                            body =  "Irregular activity has been detected investigate promptly!"
                            mail_func()
                            print(subject)
                            with open("Logs.txt", "a") as file:
                                file.write(f"\n[{today_date}] Event ID {event}: alert was triggered")
                
                except Exception as error:
                    error_log()
               

            # ------- Help Page --------- #
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
                error_log()
            
            # ------ Version Page ------- #
        elif menu_option == "3":
            print("=" * 25 + " Version 1.3.3.7 " + 25 * "=")
            with open("Logs.txt","a") as file:
                file.write(f"\n[{today_date}] User accesed script version")

            # ------ Exit Script -------- #
        elif menu_option == "4":
            print("=" * 25 + " Goodbye! " + "=" * 25)
            with open("Logs.txt","a") as file:
                file.write(f"\n[{today_date}] User terminated script")
            break
            # ----- Incorrect Input ----- #
        else:
            print("=" * 25 + "You must choose one of the optiones 1, 2, 3 or 4 !" + 25 * "=")
            with open("Logs.txt","a") as file:
                file.write(f"\n[{today_date}] Incorrect menu choice")
            continue
            
            # ------ Incorrect OS ------- #
    else:
        print("=" * 25 +"Operative system is not Windows" + 25 * "=")
        with open("Logs.txt","a") as file:
                file.write(f"\n[{today_date}] Script was run on a {sys.platform} system")
        break
        



                
            
            

                

