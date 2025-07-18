# CTF toolBox
PowerShell &amp; Python tools developed for CTFs and certification exams

(Too lazy to keep maintaining these scripts for long, feel free to edit/fix/customize as you please)
___

**Find-GPOAbuse.ps1**: Displays various GPO misconfigurations and abuse vectors (Relies on PowerView)

![gpo1](https://github.com/user-attachments/assets/81180227-deba-40cc-9e02-7d8db9a1e74e)
![gpo2](https://github.com/user-attachments/assets/baa4d1f7-4b25-4c6d-ac90-e8eb91d958e3)

---
**certInfo.ps1**: Displays information about a cert file

![certInfo](https://github.com/user-attachments/assets/d881e812-124b-479e-9c18-50f805fef285)

---
**Invoke-DomainEnumeration.(ps1|py)**: Domain enumeration in PS & Python. PS version works without any extra modules, Python version needs LDAP3.\
(Only the PS version will display potential RBCD abuse, parsing ACLs in python was a royal pain in the ass.)

![Screenshot 2025-01-16 010944](https://github.com/user-attachments/assets/4d4e97ed-19cf-45cd-aa77-15c1bb42b0f3)
![Screenshot 2025-01-16 010833](https://github.com/user-attachments/assets/e6fc91de-1ad9-4410-a1cb-c84a7cd22361)
![1736805654826](https://github.com/user-attachments/assets/7196c282-b11d-44d2-ab5e-589538b344a7)
![1736805654777](https://github.com/user-attachments/assets/b9f60f24-7b48-46f8-afb8-ec867d3cae1e)
![1736805654767](https://github.com/user-attachments/assets/d00ad209-54af-4d9c-8f4b-2b048c71717a)

---
**Invoke-NewGPO.ps1**: Creates a new empty GPO and links it to the target OU, assuming you have enough privileges. (works like a charm with membership in `Group Policy Creator Owners` or anything equally powerful).
Keep in mind that you still need privilege to link the GPO. Linking GPOs is an OU-specific permission, creating GPOs is a domain wide permission.

![1736274316707](https://github.com/user-attachments/assets/68912d4f-3406-4bdb-9ff2-2ddebf17d823)

---

**Read-FileWithSeBackupPrivilege**: Uses SeBackupPrivilege to read files/flags.

![1735424866984](https://github.com/user-attachments/assets/676cf7ab-59e8-4a4c-aee7-122adef64e66)


**Copy-FileWithSeBackupPrivilege**: Uses SeBackupPrivilege to copy files.


![image](https://github.com/user-attachments/assets/3170d958-ddb8-49e5-b9f3-63a4184805c9)

---
**raiseChild.ps1**: PowerShell version of Impacket's `raiseChild.py` - automates Child domain -> Parent domain compromise.

![image](https://github.com/user-attachments/assets/f70a80c1-9eab-4130-a9b1-31510304355b)
