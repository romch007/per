# Environment Installation


## 1. Install Visual Studio 2022

1. Download **Visual Studio 2022 Community (or higher)** from [https://visualstudio.microsoft.com/downloads/](https://visualstudio.microsoft.com/downloads/)
   
2. During installation:
   - Select the **Desktop development with C++** workload.

3. In the **Individual components** tab, ensure the following are checked:
   - **MSVC v143 - VS 2022 C++ x64/x86 Spectre-mitigated libs (Latest)**
   - **C++ ATL for latest v143 build tools with Spectre Mitigations (x86 & x64)**
   - **C++ MFC for latest v143 build tools with Spectre Mitigations (x86 & x64)**
   - **Windows Driver Kit**

4. Complete the installation and restart your computer if prompted.

## 2. Install the Windows Driver Kit (WDK)

The WDK provides the headers, libraries, and tools needed to build Windows kernel-mode drivers.

1. Download the latest Windows Driver Kit from [https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk#download-icon-for-wdk-step-3-install-the-wdk](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk#download-icon-for-wdk-step-3-install-the-wdk)

2. Run the installer and follow the prompts.  

## 3. Set up the Windows 11 Virtual Machine
 
> NOTE: We used Oracle VirtualBox, but it’s also possible to use VMware Workstation or Hyper-V.

1. Install Windows 11 in the VM.
2. Setup a **Host-Only Network Adapter** and note the VM's IP.
3. Make sure Secure Boot is disabled in VirtualBox.
4. (Optional) Disable the firewall, this can simplify things.

## 4. Install the Windows Driver Kit in the VM

1. Inside the VM, download and install the **same version** of the WDK.
2. Run in an elevated command prompt `bcdedit /set testsigning on` **and reboot**.
3. Find and run `C:\Program Files (x86)\Windows Kits\10\Remote\x64\WDK Test Target Setup x64-x64_en-us.msi`, **then reboot**.

## 5. Setup Visual Studio for Kernel Debugging

1. Click **PERDriver** -> **Properties** -> **Debugging**, then click at the right of **Remote Computer Name**.
2. Click **Add New Device**.
3. Choose a display name and enter the IP of the VM in **Network host name**, then click **Next**.
3. Put in **Host IP** the **IP of the host** inside the Host-Only network. Click **Next**/**Finish**. Wait for the installation to finish.
4. Reboot the VM.
5. In **PERDriver** -> **Properties** -> **Driver Install** -> **Deployment**, select the test VM and click on **Install/Reinstall and Verify**.
