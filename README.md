## Ransomware Defense lab 1

Using the ransomware defense repository you can test it is configured correctly on your systems in a non-intrusive way.

Step 1:
Run ChaveirosV1.py on your systems

Step 2:
In the ransomware defense repository there is the Labyrinth_keys_generatorV6.py this is the encryption key generator for labyrinth which uses fernet encryption. Chaveiros.py is programmed to catch fernet keys.

Step 3:
Run Labyrinth_keys_generatorV6.py to create the fernet key.

Step 4:
On the system you are running these go back to the terminal designated as the CISO IP in ChaveirosV2.py is running and you should see the same key displayed in the terminal.



## Ransomware Defense Lab 2

Our custom, unique, and awesome Ransomware defense lab is now live

This highly advanced home lab requires expertise in SSH, intermediate-level python source alterations, knowledge of cloud resources, VMs, OS configuration, and data analytics.

Using these defense systems, you can test their legitimacy on a cloud resource to avoid damaging your own equipment.

### To set up a ransomware defense lab using Linode cloud machines, follow these steps:

1. **Create Linode Instances**:
   - Set up two Linode instances: one as the target machine and one as the attacker machine.

2. **Setup Target Machine**:
   - Choose a vulnerable operating system (Windows, Linux, Ubuntu).
   - Install necessary dependencies, ensuring Python 3.x is installed.
   - Clone the repository and deploy `keycatcher.py` or `Chaveiros.py`:

     ```bash
     git clone https://github.com/DeadmanXXXII/Ransomeware_Defense.git
     cd Ransomeware_Defense
     python3 Chaveiros.py
     ```

   - Open a new terminal and run:

     ```bash
     python3 Labyrinth_keys_generatorV6.py
     ```

   - The IP address you set in Chaveiros.py will have collected a key. You will also see an encryption key in fernet on the terminal you ran the key generator on.

   - Note: `Chaveiros.py` was built from the reverse engineering of six pieces of ransomware. Where it says "attacker IP," it means the IP address to which you want the encryption key sent.

3. **Setup Attacker Machine**:
   - Use Kali or Parrot OS for the attacker machine.
   - Request access to the private repository for legal logging: [Ransomware](https://github.com/DeadmanXXXII/Ransomeware).
   - Prepare to upload ransomware samples as `.txt` files. (choices are a basic Conti, Rhysida or my own TMHPransomware the others are not available in this lab.)
   - Double-check IP addresses to ensure correct targeting and avoid legal issues.
   - Use SSH to access the victim machine from the attacker machine.
   - Alter the attack source, change the file appendage, and upload.

4. **Back at your victim machine**
   - The ransomware should have activated. 
Creating an encryption key and sending it to the IP delegated in Chaveiros.py.
 
   - With the ransomware active files are encrypted and a note sent to the ransomware attacker machine confirming correct targeting and attack success.

5. **With your sent off key**

   - From the defense system, decrypt your infected machine back to normal working order using De-ransomeware.py.

   - Block the IP address from making uploads.

   - Add the ransomware sample to the defense system code sequences to block.

### Lab complete.



6. **Legal and Logging Considerations**:
   - Adding all users performing the lab as collaborators on the GitHub repository for legal logging. 
   - This information will be provided if warranted.

This setup ensures a safe environment for testing ransomware defenses without risking damage to personal or company equipment.

The cloud instances I have recommended I know can be recycled easily without undue costs to linode. I have trashed countless machines and restarted them and they are ok.
