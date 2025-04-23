import pandas as pd
import tkinter as tk
from tkinter import filedialog, messagebox
from bs4 import BeautifulSoup
import time
import requests
from tkinter import scrolledtext
import subprocess
from datetime import datetime
import socket
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.edge.service import Service
from selenium.webdriver.edge.options import Options
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException


reachable_domains = list() 
keywords_list = list()
video_embedded = list()
popup_detected = list()
suspicious_flag = list()
ip_address_list = list()
IPDB_reputation = list()

IPDB_response = pd.DataFrame()
#-----------------------------------------------------------------------

def select_file():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    file_path = filedialog.askopenfilename(title="Select a CSV file", filetypes=[("CSV files", "*.csv")])
    return file_path

def read_csv(file_path):
    try:
        df = pd.read_csv(file_path)
        return df
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return None
    
# Load the CSV file 
file_path = select_file()


if file_path:
    df = read_csv(file_path)

    if df is not None:
        print("Verifying Input Dataframe...")
        print(df.head()) # Print the first few rows of the dataframe to verify
else:
    print("No file selected.") 
    exit

print("Compiling Domains...")


# Create separate lists based on the 'Action' column
block_url_domains = df[df['Action'] == 'block-url']['URL Domain'].tolist()
alert_domains = df[df['Action'] == 'alert']['URL Domain'].tolist()

# Filter the lists to contain only unique values
unique_block_url_domains = list(set(block_url_domains))
unique_alert_domains = list(set(alert_domains))


# Print the unique lists to verify
print("Unique Block URL Domains:", unique_block_url_domains)
print("Unique Alert Domains:", unique_alert_domains)

#Function to check domain reputation using VirusTotal. NOTE this is a free API and limits to 4 requests per minute and 500 per day. To come...
print("VirusTotal not yet built in. Skipping")

print("BeautifulSoup4 content check")


# Keywords to search for in the content
keywords = 'Football', 'Streams', 'free', 'movies', 'tv', 'shows', 'sports', 'live', 'streaming', 'download', 'watch', 'free movies', 'free tv shows', 'free sports', 'free streaming'


for domain in unique_alert_domains:

    url = f"https://{domain}"
    try:
        # Make a request to the URL
        response = requests.get(url, timeout=5)
        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')
        # Extract the title of the page
        title = soup.title.string if soup.title else 'No title found'
        print(f"URL: {url} - Title: {title}")

        
        if title != 'No title found':
            reachable_domains.append(url)
            # Extract the text content of the page
            content = soup.get_text()


            # Check for keywords in the content
            found_keywords = [keyword for keyword in keywords if keyword.lower() in content.lower()]
            if found_keywords:
                print(f"Keywords found in {url}: {', '.join(found_keywords)}")
                keywords_list.append(' '.join(found_keywords))
            else:
                print(f"No keywords found in {url}")
                keywords_list.append(' ')

            #Check for embedded video media
            video_tags = soup.find_all(['video', 'iframe', 'embed'])
            if video_tags:
                video_embedded.append('True')
                print(f"Embedded video media found in {url}")
            else:
                print(f"No embedded video media found in {url}")
                video_embedded.append('False')         
            
            # Check for popups
            popup_indicators = ['window.open', 'alert(', 'confirm(', 'prompt(']
            scripts = soup.find_all('script')
            popups_found = any(any(indicator in (script.string or '') for indicator in popup_indicators) for script in scripts)
            if popups_found:
                print(f"Popups detected in {url}")
                popup_detected.append('True')
            else:
                print(f"No popups detected in {url}")
                popup_detected.append('False')
            
            # Check if any of the conditions are met to set the suspicious flag
            if found_keywords or video_tags or popups_found:
                suspicious_flag.append("True")
            else:
                suspicious_flag.append("False")

            #Resolve the domain name to an IP address
            try:
                ip_address = socket.gethostbyname(domain)
                print(f"IP Address of {domain}: {ip_address}")
                ip_address_list.append(ip_address)
            except socket.gaierror:
                print(f"Could not resolve IP address for {domain}")
                ip_address_list.append("Not resolvable")
            
            #Check against AbuseIPDB API for IP address reputation
            try:
                api_url = f"https://api.abuseipdb.com/api/v2/check"
                headers = {
                    'Key': '84ece7b508c8c968c50dde195d5ba0f082acaa8a205044b10ed8633c1a5fcdee767d6fb9083a641a',  # Replace with your actual API key
                    'Accept': 'application/json'
                }
                params = {
                    'ipAddress': ip_address,  # The IP address to check
                    'maxAgeInDays': 90        # Optional: Check reports from the last 90 days
                }
                response = requests.get(api_url, headers=headers, params=params)
                if response.status_code == 200:
                    data = response.json()
                    print(f"AbuseIPDB data for {ip_address}: {data}")
                    IPDB_reputation.append(data['data']['abuseConfidenceScore'])
                else:
                    print(f"Error fetching data from AbuseIPDB for {ip_address}: {response.status_code}")
                    IPDB_reputation.append("Not resolvable")
            except requests.exceptions.RequestException as e:
                print(f"Error fetching data from AbuseIPDB for {ip_address}: {e}")
                IPDB_reputation.append("Error")


        else:
            print(f"No title found for {url}")


                
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
    
    time.sleep(1)  # Sleep for 1 second to avoid hitting the server too quickly

#-----------------------------------------------------------------------   
print(IPDB_reputation)

data = {
    'URL Domain': reachable_domains,
    'Keywords Found': keywords_list,
    'Embedded Video Media': video_embedded,
    'Popups Detected': popup_detected,
    'Confidence Score': IPDB_reputation,
    'suspicious_flag': suspicious_flag
}

#Exporting Results
df0 = pd.DataFrame(data)
print("Printing results")

export_file_path = "output.csv"
df0.to_csv(export_file_path, index=False)
print(f"Results saved to {export_file_path}")

#-----------------------------------------------------------------------


#Generating list of users

#Alert_users = df[df['Action'] == 'alert']['Source Users'].tolist()

# Filter original dataframe df by removing all columns except URL Domain and Source User
#df_modorig = df[['URL Domain', 'Source User']] 

# Removing non-suspicious URLS from analysed dataframe
suspicious_only_df = df0[df0['suspicious_flag'] == 'True']
print("Printing suspicious_only_df")
print(suspicious_only_df.head())
#Removing https://
suspicious_only_df['URL Domain'] = suspicious_only_df['URL Domain'].str.replace('https://', '', regex=False)
print("Validating suspicious_only_df")
print(suspicious_only_df.head())

#Filtering origional df to only include suspicious URLS
# This will keep only the rows in df where the 'URL Domain' is in the suspicious_only_df
filtered_df = df[df['URL Domain'].isin(suspicious_only_df['URL Domain'])]
print("Printing filtered_df")
print(filtered_df.head())
# Removing duplicates from the filtered dataframe based on 'URL Domain' and 'Source User'
# This will keep only the first occurrence of each unique combination of 'URL Domain' and 'Source User'
filtered_df_uniques = filtered_df.drop_duplicates(subset=['URL Domain', 'Source User'])
print("Printing filtered_df_uniques")
print(filtered_df_uniques.head())
# Removing extra columns from filtered dataframe
columns_to_remove = ['Cloud ReportID', 'Log Source Group ID', 'Platform type', 'Action', 'URL Category', 'URL Category List', 'From Zone', 'To Zone', 'Destination Address', 'Destination User', 'Destination Port', 'Application', 'Rule', 'Session ID', 'Device SN', 'Device Name', 'Inline ML Verdict']
filtered_df_uniques = filtered_df_uniques.drop(columns=columns_to_remove)
print("Printing filtered_df_uniques")
print(filtered_df_uniques.head())
# Create new dataframe to record how many times each user's name appears in the filtered dataframe
user_counts = filtered_df_uniques['Source User'].value_counts().reset_index()
user_counts.columns = ['Source User', 'Count']
# Save the user counts to a new CSV file
print("Printing user counts")
print(user_counts.head())
output_file_path = "user_counts.csv"
user_counts.to_csv(output_file_path, index=False)

# Function to save the DataFrames to an Excel file
def save_to_excel():
    # Get today's date in the format DDMMYY
    today_date = datetime.today().strftime('%d%m%y')
    
    # Create the filename with today's date
    filename = f"CollatedOutput{today_date}.xlsx"
    
    # Open a file dialog to select the save location
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    file_path = filedialog.asksaveasfilename(defaultextension=".xlsx", initialfile=filename, title="Save Excel File")
    
    if file_path:
        # Create a Pandas Excel writer using XlsxWriter as the engine
        with pd.ExcelWriter(file_path, engine='xlsxwriter') as writer:
            # Write each DataFrame to a different worksheet
            df0.to_excel(writer, sheet_name='Suspicious Domains', index=False)
            user_counts.to_excel(writer, sheet_name='Sheet2', index=False)
        
        print(f"DataFrames have been written to '{file_path}' with separate sheets.")
    else:
        print("Save operation cancelled.")

# Call the function to save the DataFrames to an Excel file
save_to_excel()

#-----------------------------------------------------------------------

# SELENIUM SECTION

#Popup box asking if user wants to continue to Selenium script
root = tk.Tk()
root.withdraw()  # Hide the root window
response = tk.messagebox.askyesno("Continue to Selenium Script", "Do you want to continue to action the results?")

email_address = tk.simpledialog.askstring("Email Address", "Please enter your email address for the report:")
print("Email address entered")
# If the user chooses to continue, the Selenium script will be executed.
if response:
    #-----------------------------------------------------------------------------------------------------------------
    print("Selenium script started")

    # Use Edge WebDriver
    # Removed unused import

# Set up Edge options
    edge_options = Options()
    edge_options.add_argument("--start-maximized")  # Start browser maximized
    edge_options.add_argument("--disable-extensions")  # Disable extensions

else:
    print("Selenium script cancelled.")
    exit()

webdriver_path= "Z:\Documents\Suspicious Website Detector\edgedriver_win64\msedgedriver.exe"
driver = webdriver.Edge(service=Service(webdriver_path), options=edge_options)

malicious_urls = []  # List to store user responses for each URL
reason = []  # List to store reasons for each response

def ask_reason(url):
    """Custom popup to ask for a reason with a 'Skip' button."""
    def on_submit():
        user_reason = reason_entry.get()
        if user_reason.strip():  # If the user provides a reason
            reason.append(user_reason)
        else:  # If the input is empty, add "No reason provided"
            reason.append("No reason provided")
        popup.destroy()

    def on_skip():
        reason.append("N/A")  # Add "N/A" to the reason list
        popup.destroy()
#-----------------------------------------------------------------------

    # Create the popup window
    popup = tk.Tk()
    popup.title("Reason for Response")
    popup.geometry("400x200")

    # Add a label and input box
    label = tk.Label(popup, text=f"Provide a reason for your response to '{url}':")
    label.pack(pady=10)
    reason_entry = tk.Entry(popup, width=50)
    reason_entry.pack(pady=10)

    # Add Submit and Skip buttons
    def on_submit():
        user_reason = reason_entry.get()  # Get the entered reason
        if user_reason.strip():  # If the user provides a reason
            reason.append(user_reason)
        else:  # If the input is empty, add "No reason provided"
            reason.append("No reason provided")
        popup.destroy()  # Close the popup window

    submit_button = tk.Button(popup, text="Submit", command=on_submit)
    submit_button.pack(side="left", padx=20, pady=20)
    skip_button = tk.Button(popup, text="Skip", command=on_skip)
    skip_button.pack(side="right", padx=20, pady=20)
    print("Function ran")



for index, row in suspicious_only_df.iterrows():
    url = f"https://{row['URL Domain']}"  # Ensure the URL is properly formatted

    edge_options = Options()
    edge_options.add_argument("--start-maximized")  # Start browser maximized
    edge_options.add_argument("--disable-extensions")  # Disable extensions

    driver.get(url)
    print(f"Page loaded successfully for {url}")
    driver.implicitly_wait(10)
    print("Wait passed...")
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    response = tk.messagebox.askquestion(
        "Website Malicious Check",
        f"Is the website '{url}' malicious?",
        icon='question',
        type='yesnocancel'
    )
    print("Popup box loaded")

    # Map the response to a meaningful value
    if response == "unknown":
        malicious_urls.append("unknown")
        reason.append("N/A")  # Add "N/A" for unknown responses
    elif response == "no":
        malicious_urls.append("No")
        reason.append("N/A")  # Add "N/A" for non-malicious URLs
    else:
        malicious_urls.append("yes")
        
        webdriver_path= "Z:\Documents\Suspicious Website Detector\edgedriver_win64\msedgedriver.exe"
        driver = webdriver.Edge(service=Service(webdriver_path), options=edge_options)
        driver.implicitly_wait(10)
        # Visit Palo Alto Networks URL filtering website
        driver.get("https://urlfiltering.paloaltonetworks.com/")
        # Input the URL into the input box
        input_box = WebDriverWait(driver, 15).until(
        EC.presence_of_element_located((By.ID, "id_url"))
        )
        print("Element found")

        input_box.clear()
        print("Element cleared")
        input_box.send_keys(url)
        print(f"Entered URL '{url}' into the input box.")

        email_field = WebDriverWait(driver, 130).until(
            EC.presence_of_element_located((By.ID, "id_your_email"))
        )
        print("Email field found")
        email_field.clear()
        email_field.send_keys(email_address)  # Use the email address entered by the user
        print(f"Entered email address '{email_address}' into the email field.")

        email_confirm_field = WebDriverWait(driver, 30).until(
            EC.presence_of_element_located((By.ID, "id_confirm_email"))
        )
        email_confirm_field.clear()
        email_confirm_field.send_keys(email_address)  # Use the email address entered by the user
        print(f"Entered email address '{email_address}' into the email confirmation field.")

        actioned_urls = []  # List to store actioned URLs
        actioned_urls.append(url)  # Append the URL to the list
        print(actioned_urls)

        email_field = WebDriverWait(driver, 60).until(
            EC.presence_of_element_located((By.ID, "progress_message"))
        )
        print("Submit successful found, Progressing.")


driver.quit()
# Print the malicious URLs list and reasons for verification
print("Malicious URLs List:", malicious_urls)
print("Reasons List:", reason)
