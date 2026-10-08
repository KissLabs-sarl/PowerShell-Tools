# PowerShell Tools

Scripts PowerShell d'administration Windows, par KissLabs.

| Script | Rôle |
| --- | --- |
| [`Check-Windows11Upgrade.ps1`](Check-Windows11Upgrade.ps1) | Vérifie si un poste est prêt pour la mise à niveau vers Windows 11 25H2. |

---

## Check-Windows11Upgrade.ps1

Contrôle de préparation à la mise à niveau vers **Windows 11 25H2** (build 26200), pensé pour être lancé
à la main ou déployé en masse (Intune, RMM, GPO). Le résultat est affiché en clair et renvoyé sous forme
de code de sortie exploitable.

### Contrôles effectués

1. **Système d'exploitation** : édition client (pas Windows Server ; Windows Enterprise multi-session
   / AVD est traité comme un poste client), version source compatible
   (Windows 10 2004 ou plus récent avec la mise à jour du 14 septembre 2021), version déjà installée
   (25H2 ou plus récent, comparaison sur le numéro de build), édition LTSC, détection machine virtuelle,
   espace disque libre.
2. **Prérequis matériels Microsoft** (CPU, RAM, TPM 2.0, Secure Boot, stockage) via le script officiel
   [`HardwareReadiness.ps1`](https://aka.ms/HWReadinessScript).
3. **DirectX 12 / WDDM 2.0** via `dxdiag` (simple avertissement sur une machine virtuelle).
4. **État Windows** : redémarrage en attente, service Windows Update, verrouillage de version
   `TargetReleaseVersion` / `ProductVersion` par GPO ou par Intune (MDM), WSUS. Sous Windows 10, un
   verrouillage sans `ProductVersion` = Windows 11 est considéré comme bloquant.
5. **Safeguard Hold** Microsoft (blocage de compatibilité posé par Microsoft sur la machine), lu dans
   les données de l'évaluation de compatibilité Windows (Appraiser) pour la version cible (clé `GE25H2`),
   en tenant compte de la stratégie `DisableWUfBSafeguards`.

### Prérequis

- Windows PowerShell 5.1 (PowerShell 7 fonctionne aussi).
- Exécution **en administrateur** (ou en SYSTEM).
- Accès HTTPS à `aka.ms` / `download.microsoft.com`, sauf si une copie locale de `HardwareReadiness.ps1`
  est fournie avec `-HardwareScriptPath`.

### Utilisation

```powershell
# Contrôle standard
.\Check-Windows11Upgrade.ps1

# Poste sans accès Internet : copie locale du script Microsoft
.\Check-Windows11Upgrade.ps1 -HardwareScriptPath "\\serveur\partage\HardwareReadiness.ps1"

# Conserver les fichiers temporaires (HardwareReadiness.ps1, DxDiag.xml) pour analyse
.\Check-Windows11Upgrade.ps1 -KeepTemp

# Journal dans un autre dossier
.\Check-Windows11Upgrade.ps1 -LogDirectory "D:\Logs"
```

| Paramètre | Défaut | Description |
| --- | --- | --- |
| `-RecommendedFreeSpaceGB` | `30` | Espace libre recommandé sur le disque système (avertissement non bloquant). |
| `-KeepTemp` | — | Conserve le dossier temporaire au lieu de le supprimer. |
| `-HardwareScriptPath` | — | Copie locale de `HardwareReadiness.ps1` à utiliser au lieu du téléchargement. |
| `-LogDirectory` | `%ProgramData%\KissLabs\Logs` | Dossier du fichier journal. |

L'aide complète est disponible avec `Get-Help .\Check-Windows11Upgrade.ps1 -Full`.

### Codes de sortie

| Code | Résultat | Signification |
| --- | --- | --- |
| `0` | `READY` | Le poste peut être mis à niveau vers 25H2. |
| `0` | `ALREADY_CURRENT` | 25H2 (ou plus récent) est déjà installé et le matériel est conforme. |
| `1` | `NOT_CAPABLE` | Au moins un prérequis obligatoire n'est pas respecté (matériel, OS source, GPU). |
| `2` | `UNDETERMINED` | Le contrôle matériel Microsoft n'a pas pu conclure. |
| `2` | `ALREADY_CURRENT_CHECK_INCOMPLETE` | Déjà à jour, mais le contrôle matériel n'a pas pu conclure. |
| `2` | `ERROR` | Erreur d'exécution (pas de droits administrateur, téléchargement impossible, signature invalide…). |
| `3` | `CAPABLE_BUT_BLOCKED` | Matériel compatible, mais une stratégie GPO ou Intune (`TargetReleaseVersion` / `ProductVersion`), un Safeguard Hold ou une édition LTSC bloque la mise à niveau. |
| `4` | `ALREADY_CURRENT_NOT_COMPLIANT` | Déjà à jour, mais le matériel ne respecte pas tous les prérequis. |

Les deux dernières lignes de la sortie (`FinalResult` et `ExitCode`) résument le résultat, y compris en
cas d'`ERROR`.

### Journal

Chaque exécution écrit un fichier dédié
`Check-Windows11Upgrade_<POSTE>_<AAAAMMJJ-HHMMSS>_<PID>.log` dans `%ProgramData%\KissLabs\Logs` (ou
`-LogDirectory`). Chaque ligne de contrôle est horodatée et porte un niveau (`INFO`, `OK`, `WARN`, `FAIL`,
`ERROR`). Si le journal ne peut pas être créé, un avertissement est affiché et le contrôle continue.
Le journal n'est ouvert qu'après la vérification des droits administrateur, et un dossier redirigé
(jonction ou lien symbolique) est refusé. Les fichiers ne sont pas purgés automatiquement.

### Notes de déploiement

- **Sécurité** : `HardwareReadiness.ps1` n'est exécuté que si sa signature Authenticode est valide et
  émise pour *Microsoft Corporation*, ou si son empreinte SHA-256 correspond à la version officielle
  connue. Dans le cas contraire, le contrôle s'arrête en `ERROR`.
- **Copie locale** (`-HardwareScriptPath`) : utiliser le fichier tel que téléchargé depuis Microsoft.
  Toute modification, y compris une conversion des fins de ligne (par exemple via Git), invalide la
  signature.
- **Intune / hôte 32 bits** : Intune lance par défaut les scripts en PowerShell 32 bits. Le script se
  relance alors automatiquement en PowerShell 64 bits, sans quoi une partie du registre (Safeguard Hold,
  redémarrage en attente) ne serait pas visible. Le code de sortie est conservé.
- **Machines virtuelles** : un GPU virtuel sans DirectX 12 produit un avertissement, pas un blocage.
- **Erreurs WMI** : si le script Microsoft conclut à `NOT CAPABLE` uniquement parce qu'une requête WMI a
  échoué, le résultat est ramené à `UNDETERMINED` et les erreurs sont affichées.
- Les données Safeguard Hold datent de la dernière exécution de l'Appraiser : leur date est affichée,
  avec un avertissement au-delà de 30 jours.
