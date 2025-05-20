# 🛡️ CVE Watcher

**CVE Watcher** est un script Python qui vous alerte automatiquement par e-mail lorsqu'une nouvelle vulnérabilité (CVE) est publiée sur le [NVD](https://nvd.nist.gov/) en lien avec un outil ou produit spécifique (ex : GLPI, Fortinet, Zimbra, WordPress…).

Il est conçu pour s’exécuter régulièrement (ex. chaque heure) et ne vous contacte **que lorsqu’une nouvelle faille est détectée**. Parfait pour une **veille cybersécurité ciblée** sans spam.

---
## 🚀 Fonctionnalités

- 🔍 Recherche des CVE par mot-clé (nom d'outil, éditeur, techno, etc.)
- 📧 Notification par e-mail uniquement en cas de nouveauté
- 🧠 Conservation du dernier CVE détecté localement
- 🕒 Prévu pour une exécution automatique (cron ou tâche planifiée)
- 🔒 Compatible avec Gmail via mot de passe d'application
---

## ⚙️ Installation
1. Clonez ce dépôt :
```bash
