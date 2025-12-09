#   win_logs.py
#   Script för att läsa och filtrera windows säkerhetsloggar med hjälp av pywin32
#   Måste som köras administratör och kräver pywin32
#   
#   Skriven av Nicolas.H

# --Imports-- #
from itertools import groupby
import win32evtlog
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


# --Variables-- #

i = 0
handle = win32evtlog.OpenEventLog(None, "Security")                              # öpnnar securityloggen på den lokala datorn
flags = win32evtlog.EVENTLOG_FORWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ  # sätta flagga för hur loggarna ska läsas
sec_records = []                                                                 # skapa en lista för att lagra loggar

sender_email = ""
receiver_mail = ""

subject = "Multiple failed logon attempts"
body =  "Event ID: 4625 has appeared multiple times, investigate promptly"

message = MIMEMultipart()
message["From"] = sender_email
message["To"] = receiver_mail
message["Subject"] = subject




# --Main code-- #

while True:
    sec_logs = win32evtlog.ReadEventLog(handle, flags, 0)    # läser loggarna från handle, hur den läser dem, och från vilken position
    if not sec_logs:                                         # Om det inte finns några logs kvar att läsa hoppa ur loopen
        break                                                # 
    sec_records.extend(sec_logs)                             # lägger till de lästa loggarna i listan all_records





for sec_log in sec_records:                                  # 
#   print(f"Event ID: {sec_logs.EventID & 0xFFFF}")          # skriver ut event ID  // kommer ta bort den senare bara för att se att det funkar för nu
   i += 1
    


evt_id = [sec_logs.EventID & 0xFFFF for sec_logs in sec_records] 
for event,group in groupby(evt_id):
    if event == 4625:
        fail_log = sum(1 for _ in group)
        if fail_log > 1:
            print(f"{event} is repeated {fail_log} in a row")
            





print(f"{i} Loggar lässta.")                               # Skriver ut hur många loggar som hittades

win32evtlog.CloseEventLog(handle)                          # Stänger ner loggen