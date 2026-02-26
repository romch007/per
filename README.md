# Proof of Concept – BYOVD Lenovo (CVE-2025-8061)

⚠️ **Usage strictement académique / environnement de laboratoire uniquement.**  
Ce PoC doit être exécuté dans une machine virtuelle isolée.

---

## 🖥 Environnement recommandé

Pour garantir la stabilité et la reproductibilité :

- **Windows 11 25H2 – Build 26200.7623**
- Machine virtuelle (VirtualBox dans notre cas)
- Snapshot recommandé avant exploitation

L’exploit dépend fortement :
- de la version exacte de Windows,
- de la configuration des sécurités,
- du comportement micro-architectural exposé par l’hyperviseur.

---

## 🔐 1. Désactivation des protections nécessaires

Certaines protections doivent être désactivées pour permettre l’exécution du PoC.

### ➤ Désactiver VBS (Virtualization-Based Security)

1. `Win + R` → taper `msinfo32`
2. Vérifier que **"Sécurité basée sur la virtualisation"** est **désactivée**

Si activée :

- Ouvrir `gpedit.msc`
- Aller dans  
  `Configuration ordinateur → Modèles d’administration → Système → Device Guard`
- Mettre **"Activer la sécurité basée sur la virtualisation"** sur *Désactivé*
- Redémarrer

Guide détaillé si nécessaire :  
https://learn.microsoft.com/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity

---

### ➤ Désactiver Core Isolation / Memory Integrity

1. Ouvrir **Sécurité Windows**
2. Aller dans **Sécurité des appareils**
3. Cliquer sur **Isolation du noyau**
4. Désactiver **Intégrité de la mémoire**
5. Redémarrer la VM

Ces mécanismes empêchent :
- certaines modifications noyau,
- l’exécution de code non signé,
- le contournement de protections comme SMEP.

---

## 📦 2. Installation du driver vulnérable

Dans la VM (⚠️ Exécuter PowerShell en tant qu’administrateur) :

```powershell
cd scripts
powershell -ExecutionPolicy Bypass -File .\installlenovo.ps1
```
Cela installe le driver LnvMSRIO.sys, exposant les IOCTL vulnérables nécessaires à l’exploitation.

---

## 🛠 3. Compilation de l’exploit

Compiler :
```code
VulnerableDriver/Exploit/Exploit.c
```
Avec :
- Visual Studio 2022+
- MSVC v143
- Windows SDK

Générer :
```cmd
Exploit.exe
```
---

## 🚀 4. Exécution

Ouvrir cmd.exe en utilisateur standard (non administrateur) :
```cmd
Exploit.exe
```
L’exploit réalise :
- désactivation temporaire de SMEP/SMAP,
- exécution d’un shellcode,
- vol du token SYSTEM,
- élévation de privilèges vers **NT AUTHORITY\SYSTEM**.

Si l’exploitation réussit, le processus courant dispose désormais des privilèges SYSTEM.

---

## 🧪 Vérifications utiles

- whoami → doit afficher nt authority\system
- whoami /groups → vérifier le niveau d’intégrité
- Snapshot recommandé avant chaque test

## ❗ Dépannage

Si la VM crash :
- Vérifier que VBS est bien désactivé
- Vérifier que Core Isolation est désactivé
- Vérifier que la build correspond bien à 26200.7623
- S’assurer que la valeur CR4 utilisée correspond à celle du système cible
- Vérifier que les adresses ROP correspondent à la version de ntoskrnl.exe

## 📌 Remarques importantes

- L’exploit est build-dépendant
- Les adresses ROP varient selon la version Windows
- La valeur de CR4 dépend du CPU / hyperviseur
- Un environnement Intel et AMD peut produire des comportements différents

## 🎓 Contexte académique

Ce PoC illustre :

- l’exploitation d’un driver vulnérable (BYOVD),
- l’utilisation d’une primitive write-what-where en Ring 0,
- le contournement de protections modernes (SMEP, kASLR, KVA Shadow),
- l’élévation de privilèges locale vers SYSTEM.
