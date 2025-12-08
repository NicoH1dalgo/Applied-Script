import win32evtlog
i = 0
# öpnna securityloggen
handle = win32evtlog.OpenEventLog(None, "Security")
# sätta flaggar för att läsa loggar
flags = win32evtlog.EVENTLOG_FORWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
# skapa en lista för att lagra loggar
all_records = []
# läsa loggarna
while True:
    records = win32evtlog.ReadEventLog(handle, flags, 0)
    if not records:
        break
    all_records.extend(records)
# Process and print each record
for record in all_records:
    #  kommer ta bort den senare bara för att se att det funkar för nu
    print(f"Event ID: {record.EventID & 0xFFFF}")
    
    
    
    i += 1
    
print(f"{i} Log records found")

# Close the event log handle
win32evtlog.CloseEventLog(handle)