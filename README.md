# prisma_unusual_tld_analysis
Project aimed at taking exported Prisma logs and identifying suspicious websites visited. 

This requires a export of the 'URL' filter from Palo Alto's Strata Cloud manager logs. 

If obtaining this file this must be run in a sandbox. This project aims at analysing domains visited with unusual TLDs (your filter used in Strata is your own) and depending on who you're monitoring may link to outright malicious websites. 

There is an option to launch a part two of the script which will direct malicious results to Palo Alto's URL categorisation service for recategorisation requests. There is NO API option for this so there are 2x CAPTCHA's which must be completed per positive result. 
