#   win_logs.py
#
#   Script för att läsa och filtrera windows säkerhetsloggar med hjälp av pywin32
#   Skickar även ett mail om "onormalt" beteende uppstår baserat på regler
#   Måste som köras administratör och kräver pywin32
#   
#   ----------## Skriven av Nicolas.H ##----------

# --Imports-- #
from itertools import groupby
import win32evtlog
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


# --Log Reading Settings-- #

handle = win32evtlog.OpenEventLog(None, "Security")                               # öpnnar securityloggen på den lokala datorn
flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ # sätta flagga för hur loggarna ska läsas
sec_records = []                                                                  # skapa en lista för att lagra loggar

# --Email config-- #
sender_email = ""
receiver_mail = ""
password = ""

# --Main code-- #

while True:
    sec_logs = win32evtlog.ReadEventLog(handle, flags, 0)                         # läser loggarna från handle, hur den läser dem, och från vilken position
    if not sec_logs:                                                              # Om det inte finns några logs kvar att läsa hoppa ur loopen
        break                                                                     # 
    sec_records.extend(sec_logs)                                                  # lägger till de lästa loggarna i listan all_records


evt_id = [sec_logs.EventID & 0xFFFF for sec_logs in sec_records] 
for event,group in groupby(evt_id):
    if event == 4625:
        fail_log = sum(1 for _ in group)
        if fail_log > 5:
            # --Create Email Content-- #
            subject = "Event ID : 4625 Multiple Failed logon attempts! *HIGH*"
            body =  "Irregular activity has been detected investigate promptly!"
            message = MIMEMultipart()
            message["From"] = sender_email
            message["To"] = receiver_mail
            message["Subject"] = subject
            message.attach(MIMEText(body, "plain"))
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                server.login(sender_email, password)  
                server.send_message(message)

    elif event == 4720:
        fail_log = sum(1 for _ in group)
        if fail_log > 5:
            # --Create Email Content-- #
            subject = "Event ID : 4720 New Account Has Been Created! *MED*"
            body =  "Irregular activity has been detected investigate!"
            message = MIMEMultipart()
            message["From"] = sender_email
            message["To"] = receiver_mail
            message["Subject"] = subject
            message.attach(MIMEText(body, "plain"))
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                server.login(sender_email, password)  
                server.send_message(message)


            

win32evtlog.CloseEventLog(handle)                                                  # Stänger ner loggen

