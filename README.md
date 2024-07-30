# Ransomeware_Defense

## These scripts are for catching encryption keys made on a system and sending them off network.

This has been derived from the same system ransomware uses. When the key is generrated in a readable logic it sends one to the CISO's phone if they wish.
Stay one step ahead have a key catcher.

## Ransomware Defense Lab 1

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

   - Both terminals should display the same encryption key.

   - Note: `Chaveiros.py` was built from the reverse engineering of six pieces of ransomware. Where it says "attacker IP," it means the IP address to which you want the encryption key sent.

3. **Setup Attacker Machine**:
   - Use Kali or Parrot OS for the attacker machine.
   - Request access to the private repository for legal logging: [GitHub Repository](https://github.com/DeadmanXXXII/Ransomeware).
   - Prepare to upload ransomware samples as `.txt` files.
   - Double-check IP addresses to ensure correct targeting and avoid legal issues.
   - Use SSH to access the victim machine from the attacker machine.
   - Alter the attack source, change the file appendage, and upload.

4. **Legal and Logging Considerations**:
   - Adding all users performing the lab as collaborators on the GitHub repository for legal logging. 
   - This information will be provided if warranted.

This setup ensures a safe environment for testing ransomware defenses without risking damage to personal or company equipment.
The cloud instances I have recommended I know can be recycled easily without undue costs to linode. I have trashed countless machines and restarted them and they are ok.
