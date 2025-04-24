# prisma_unusual_tld_analysis
Overview

Project aimed at taking exported Prisma logs and identifying suspicious websites visited.

Inspiration:
One too many times a user has triggered clickfix or the like by visiting dodgy domains. As what I was initially looking for were illecit streaming websites these sites often had repeat visits.

Logic Flow:
1. Import exported Prisma logs
2. Run automated checks looking for suspicious elements in malicious websites
3. Check domain against AbuseIPDB
4. Create an automatic verdict
5. Save results to a CSV
   (optional)
6. Webdriver visit each flagged site and make a malicious verdict
7. If a malicious verdict is made visit Palo Alto's URL filtering website and (with some help filling forms) complete a recategorisation request
8. Export submitted domains to a list. Append if a list already exists.

Disclaimers
1. I am by no means an expert at Python and this is still very much a work in progress. There is VERY little error or exception handling built in currently. Lots of spaghetti code, low efficency. Likely some duplicated functions or unneccecary lines.
2.  This requires a export of the 'URL' filter from Palo Alto's Strata Cloud manager logs.
3.  his script MUST BE RUN IN A SANDBOX. 
4.  here is NO API option for Palo Alto's URL submission process so this has to be run via web driver. There are 2x CAPTCHA's which must be completed per positive result. 

