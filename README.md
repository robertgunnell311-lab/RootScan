# RootScan (root + non-root in one app)
Auto-detects root. Without root (or with "Force non-root" ticked) it scans shared storage and installed apps.

## Get the APK without Android Studio
1. Create a free GitHub repo and upload everything in this folder (keep the .github folder).
2. Open the Actions tab > "Build APK" > wait ~5 min.
3. Download the "RootScan-apk" artifact, unzip, install app-debug.apk (allow "install unknown apps").

## Or build locally
Open this folder in Android Studio > Build > Build APK(s).

Add known-malware SHA-256 hashes to app/src/main/assets/bad_hashes.txt.
