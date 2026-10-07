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

1. **Système d'exploitation** : édition client (pas Windows Server), version source compatible
   (Windows 10 2004 ou plus récent avec la mise à jour du 14 septembre 2021), version déjà installée,
   détection machine virtuelle, espace disque libre.
2. **Prérequis matériels Microsoft** (CPU, RAM, TPM 2.0, Secure Boot, stockage) via le script officiel
   [`HardwareReadiness.ps1`](https://aka.ms/HWReadinessScript).
3. **DirectX 12 / WDDM 2.0** via `dxdiag` (simple avertissement sur une machine virtuelle).
4. **État Windows** : redémarrage en attente, service Windows Update, GPO `TargetReleaseVersion` /
   `ProductVersion`, WSUS.
5. **Safeguard Hold** Microsoft (blocage de compatibilité posé par Microsoft sur la machine).

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
```

| Paramètre | Défaut | Description |
| --- | --- | --- |
| `-RecommendedFreeSpaceGB` | `30` | Espace libre recommandé sur le disque système (avertissement non bloquant). |
| `-KeepTemp` | — | Conserve le dossier temporaire au lieu de le supprimer. |
| `-HardwareScriptPath` | — | Copie locale de `HardwareReadiness.ps1` à utiliser au lieu du téléchargement. |

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
| `3` | `CAPABLE_BUT_BLOCKED` | Matériel compatible, mais une GPO ou un Safeguard Hold bloque la mise à niveau. |
| `4` | `ALREADY_CURRENT_NOT_COMPLIANT` | Déjà à jour, mais le matériel ne respecte pas tous les prérequis. |

Les deux dernières lignes de la sortie (`FinalResult` et `ExitCode`) résument le résultat.

### Notes de déploiement

- **Sécurité** : `HardwareReadiness.ps1` n'est exécuté que si sa signature Authenticode est valide et
  émise pour *Microsoft Corporation*. Dans le cas contraire, le contrôle s'arrête en `ERROR`.
- **Intune / hôte 32 bits** : Intune lance par défaut les scripts en PowerShell 32 bits. Le script se
  relance alors automatiquement en PowerShell 64 bits, sans quoi une partie du registre (Safeguard Hold,
  redémarrage en attente) ne serait pas visible. Le code de sortie est conservé.
- **Machines virtuelles** : un GPU virtuel sans DirectX 12 produit un avertissement, pas un blocage.
- Les données Safeguard Hold proviennent de l'évaluation de compatibilité Windows (Appraiser) et
  peuvent dater de sa dernière exécution.
