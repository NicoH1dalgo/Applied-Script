\# Windows Security Log Scanner



A Python script that monitors Windows Security Event Logs and sends email alerts when suspicious activity is detected.



\## 🔍 Features



\- Monitors Windows Security logs in real-time

\- Detects failed login attempts (brute-force attacks)

\- Detects audit log tampering

\- Automatic email alerts for suspicious activity

\- Simple menu-driven interface



\##📋 Prerequisites



\- \*\*Operating System\*\*: Windows

\- \*\*Python\*\*: 3.x

\- \*\*Privileges\*\*: Administrator rights required

\- \*\*Dependencies\*\*: 

&nbsp; - `pywin32`

&nbsp; - `smtplib` (standard library)



\##  Installation



1\. Clone the repository:

&nbsp;	

git clone https://github.com/yourusername/win-security-log-scanner.git

cd win-security-log-scanner



2\. Install required dependencies:



pip install pywin32





3\. Configure email settings in `win\_logs.py`:



sender\_email = "your-email@gmail.com"

receiver\_mail = "recipient@example.com"

password = "your-app-password"





\### Gmail Configuration



For Gmail, you'll need to use an \*\*App Password\*\* instead of your regular password:

1\. Go to \[Google Account Settings](https://myaccount.google.com/apppasswords)

2\. Generate an App Password

3\. Use that password in the script



\## 💻 Usage



1\. \*\*Run as Administrator\*\*:

&nbsp;  - Right-click Command Prompt

&nbsp;  - Select "Run as administrator"

&nbsp;  - Navigate to script directory



2\. \*\*Execute the script\*\*:



python win\_logs.py





3\. \*\*Select from menu\*\*:

&nbsp;  - `1` - Security log scan

&nbsp;  - `2` - Help page

&nbsp;  - `3` - Quit



\##  Monitored Events



| Event ID | Description | Threshold | Risk Level |

|----------|-------------|-----------|------------|

| 4625 	   | Fail. Logon | 5+ fail   | HIGH       |

| 1102     | Aud.LogClear| 1+ occurr | HIGH       |

Feel free to add you own events



\##  Alert System



When suspicious activity is detected, the script automatically sends an email alert with:

\- Event ID that triggered the alert

\- Brief description of the threat

\- Urgency level (HIGH)



\##  Security Notes



\- \*\*Never commit credentials\*\* to version control

\- Consider using environment variables for sensitive data

\- Regularly review and update monitored event IDs

\- Keep detailed logs of all alerts for forensic purposes





\### Email not sending

\- Verify email credentials are correct

\- Check Gmail App Password is configured

\- Ensure SMTP settings are correct (smtp.gmail.com:587)

\- Check firewall settings



\### Import Error for win32evtlog

Install pywin32: `pip install pywin32`



\## 📝 How It Works



1\. Opens Windows Security event log

2\. Reads all log entries sequentially

3\. Groups events by Event ID

4\. Counts occurrences of monitored events

5\. Compares counts against defined thresholds

6\. Sends email alert if threshold exceeded



\##  Author



\*\*Nicolas.H\*\*



\##  Future Improvements



\- \[ ] Add more event IDs to monitor

\- \[ ] Database logging for alert history

\- \[ ] Web dashboard for monitoring

\- \[ ] Support for multiple email recipients

\- \[ ] Configurable thresholds via config file

\- \[ ] Slack/Discord webhook integration



\##  Disclaimer



This tool is for legitimate security monitoring purposes only. Ensure you have proper authorization before monitoring any system.

