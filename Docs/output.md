## Report Index Page

This is the main index page of the generated forensic report.


<img width="988" height="198" alt="image" src="https://github.com/user-attachments/assets/800a481d-12d6-4584-ae47-9f7a9dc19d10" />



- This page acts as a central navigation panel for all collected artifacts  
- Each section represents a specific category of forensic data  

### Features

- Displays basic scan information:
  - Investigator name  
  - Scan start time  
  - Analysis time range  

- Provides categorized access to artifacts:
  - Windows Information  
  - Prefetch Files  
  - Services  
  - Startup Folders  
  - Registry  
  - USB Artifacts  
  - Firewall Artifacts  
  - Browser Artifacts  
  - Live Connections  
  - Running Tasks  
  - File System Artifacts  
  - Windows Defender Logs  
  - Scheduled Tasks  

### Navigation

- Each item in the table is clickable  
- Clicking a section opens the corresponding detailed artifact report  

This structure allows quick navigation and efficient analysis of collected forensic data.


## Artifact View (Detailed Reports)

When a user selects any artifact from the main menu, the detailed report is displayed below the index section.

### Behavior

- Each artifact opens within the same page (embedded view)  
- The interface uses HTML frame-based rendering for structured navigation  

<img width="1530" height="480" alt="image" src="https://github.com/user-attachments/assets/ba53c5c3-6429-4bb7-92ad-3a4e69c78e43" />



### Viewing Options

- Artifacts are displayed inline for quick access  
- For better visibility and detailed analysis:
  - Right-click on the artifact view  
  - Select **"Open frame in new tab"** (or similar option depending on the browser)  

### Notes

- Opening in a new tab provides:
  - Full-screen view  
  - Easier navigation for large datasets  
  - Better readability for long tables  

- Sensitive information in reports may be redacted for security and privacy reasons  


## No Artifacts Found


<img width="512" height="306" alt="image" src="https://github.com/user-attachments/assets/839ee8f1-e3b0-4d15-9002-875c58a42eed" />



If the system does not contain a particular artifact, the tool will display a message indicating that no related data was found.

### Behavior

- The tool handles missing artifacts gracefully  
- Instead of errors, a clear message is shown:
  
  **"No Related Artifacts Were Identified on This System"**

- This ensures:
  - Clean report structure  
  - No confusion for the investigator  
  - Consistent user experience across all modules  
