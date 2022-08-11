# ESET Quarantine Extraction Toolset
Copyright (c) 2022, tan2pow16; all rights reserved.

---

Package quarantined malware samples from ESET quarantine folder on a device into a safe-to-handle bundles that can be easily transferred. Send the export program to your friends who constantly gets malware (and use ESET) but have no idea how interesting and dangerous those live samples can be!  
  
**ATTENTION:** Do NOT run the `extract` program outside a properly setup VM dedicated to malware analysis.  

---

## Export
The `export` tool exports all quarantined files on a computer and deletes the quarantine entries from the device. The exported bundle will be placed in the `Desktop` folder with the name `Nod32MalPack_<epoch_time>.bin`. The files are by default encoded by ESET and thus safe to handle even for non-technical users. You can send the export program to those who constantly receive live malware from emails and have absolutely no idea about how their computer deals with them. All they have to to is to run the program and send the bundled package on desktop to you!

---

## Extract
The `extract` tool extracts all bundle packages created by the `export` tool under the specified folder to the destination directory, organized by the timestamps of detection occurrence.  
**FINAL WARNING:** This tool will re-create *live malware* files on the device it runs on. Do NOT proceed if you have ANY doubt. The extracted files are NOT safe to handle by design. You should use this tool *ONLY* under a *properly setup* virtual machine dedicated to malware analysis.
