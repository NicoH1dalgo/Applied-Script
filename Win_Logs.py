#   win_logs.py
#   Script för att läsa windows säkerhetsloggar med hjälp av pywin32
#   Måste som köras administratör
#   
#   Skriven av Nicolas.H

# --Imports-- #
import win32evtlog

# --Variables-- #
i = 0
handle = win32evtlog.OpenEventLog(None, "Security")                              # öpnnar securityloggen på den lockala datorn
flags = win32evtlog.EVENTLOG_FORWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ  # sätta flagga för hur loggarna ska läsas
all_records = []                                                                 # skapa en lista för att lagra loggar




# --main code-- #
while True:
    sec_logs = win32evtlog.ReadEventLog(handle, flags, 0)    # läser loggarna från handle, hur den läser dem, och från vilken position
    if not sec_logs:
        break
    all_records.extend(sec_logs)                             # lägger till de lästa loggarna i listan all_records

for sec_logs in all_records:
    print(f"Event ID: {sec_logs.EventID & 0xFFFF}")          # skriver ut event ID  // kommer ta bort den senare bara för att se att det funkar för nu
  

    
    
    
    i += 1
    
print(f"{i} Loggar.")                               # skriver ut hur många loggar som hittades

win32evtlog.CloseEventLog(handle) #Stänger ner loggen