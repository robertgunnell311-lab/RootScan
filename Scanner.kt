package com.example.rootscan

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Environment
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

data class Finding(val severity: String, val title: String, val detail: String)

object Root {
    fun run(cmd: String): List<String> = try {
        val p = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))
        val out = p.inputStream.bufferedReader().readLines()
        p.waitFor()
        out
    } catch (e: Exception) { emptyList() }

    fun available() = run("id").any { it.contains("uid=0") }
    fun q(path: String) = "'" + path.replace("'", "'\\''") + "'"
}

class Scanner(private val ctx: Context, private val step: (String) -> Unit) {

    private val prune = "-path /proc -o -path /sys -o -path /dev -o -path /storage -o " +
        "-path /mnt -o -path /sdcard -o -path /apex -o -path /acct -o -path /data/media"

    private val riskyExt = setOf("apk", "dex", "jar", "so", "sh", "elf", "bin", "exe", "scr", "bat")
    private val doubleExt = Regex(
        ".+\\.(jpe?g|png|gif|pdf|docx?|xlsx?|txt|mp3|mp4|zip)\\.(apk|sh|exe|bat|scr|dex|jar|so|elf|bin)$",
        RegexOption.IGNORE_CASE
    )
    private val suAllow = listOf("/su", "magisk", "/debug_ramdisk", "ksud", "busybox")
    private val scriptPattern = Regex("(/dev/tcp/|nc -e |base64 -d.*\\| *sh|wget .*\\| *sh|curl .*\\| *sh)")
    private val eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    private fun loadBad() = ctx.assets.open("bad_hashes.txt").bufferedReader().readLines()
        .map { it.trim().lowercase() }.filter { it.isNotEmpty() && !it.startsWith("#") }.toSet()

    fun run(vtKey: String, useRoot: Boolean): List<Finding> =
        if (useRoot) runRooted(vtKey) else runNonRoot(vtKey)

    // ---------------------------------------------------------------- ROOTED
    private fun runRooted(vtKey: String): List<Finding> {
        val f = mutableListOf<Finding>()
        val bad = loadBad()

        step("Checking SUID/SGID binaries across /…")
        Root.run("find / \\( $prune \\) -prune -o -type f \\( -perm -4000 -o -perm -2000 \\) -print 2>/dev/null")
            .forEach { p ->
                val ok = suAllow.any { p.contains(it, true) }
                f += Finding(if (ok) "INFO" else "HIGH",
                    if (ok) "Root helper binary (expected on rooted device)" else "Unexpected SUID/SGID binary", p)
            }

        step("Checking system partitions for world-writable files…")
        Root.run("find /system /vendor /product /system_ext -type f -perm -0002 2>/dev/null")
            .take(200).forEach { f += Finding("HIGH", "World-writable system file", it) }

        step("Checking boot-time persistence scripts…")
        Root.run("find /data/adb/service.d /data/adb/post-fs-data.d /data/adb/late_start -type f 2>/dev/null")
            .forEach { f += Finding("MEDIUM", "Boot-time root script (review it)", it) }
        val mods = Root.run("ls /data/adb/modules 2>/dev/null")
        if (mods.isNotEmpty()) f += Finding("INFO", "Root modules installed", mods.joinToString(", "))

        step("Listing files in user storage and /data/local/tmp…")
        val files = Root.run("find /data/media/0 /data/local/tmp -type f 2>/dev/null")
        val hashTargets = mutableListOf<String>()
        var elfChecks = 0
        files.forEachIndexed { i, p ->
            if (i % 500 == 0) step("Analyzing storage files $i/${files.size}…")
            val name = p.substringAfterLast('/')
            val ext = name.substringAfterLast('.', "").lowercase()
            if (doubleExt.matches(name)) {
                f += Finding("HIGH", "Disguised double-extension file", p); hashTargets += p
            } else if (ext in riskyExt) {
                hashTargets += p
                if (ext == "apk") f += Finding("MEDIUM", "Installable APK sitting in storage", p)
                if (ext == "sh" || ext == "elf" || ext == "bin")
                    f += Finding("MEDIUM", "Executable/script in storage", p)
            } else if ((ext.isEmpty() || p.startsWith("/data/local/tmp")) && elfChecks < 400) {
                elfChecks++
                if (Root.run("head -c 4 ${Root.q(p)} | od -An -tx1").any { it.contains("7f 45 4c 46") }) {
                    f += Finding("HIGH", "Disguised native executable (ELF)", p); hashTargets += p
                }
            }
        }

        step("Searching for EICAR test signature and script patterns…")
        Root.run("grep -rIl '$eicar' /data/media/0 /data/local/tmp 2>/dev/null")
            .forEach { f += Finding("HIGH", "EICAR test virus signature (scanner works)", it) }
        Root.run("grep -rlE '(/dev/tcp/|nc -e |base64 -d.*\\| *sh|wget .*\\| *sh|curl .*\\| *sh)' " +
            "--include=*.sh /data/media/0 /data/local/tmp 2>/dev/null")
            .forEach { f += Finding("HIGH", "Script with reverse-shell/downloader pattern", it) }

        step("Collecting installed APKs…")
        val installed = Root.run("find /data/app -name '*.apk' 2>/dev/null")
        val all = hashTargets + installed
        val hashes = LinkedHashMap<String, String>()
        all.chunked(40).forEachIndexed { i, chunk ->
            step("Hashing files ${minOf((i + 1) * 40, all.size)}/${all.size}…")
            Root.run("sha256sum " + chunk.joinToString(" ") { Root.q(it) } + " 2>/dev/null").forEach { line ->
                val parts = line.split(Regex("\\s+"), 2)
                if (parts.size == 2) hashes[parts[1].trim()] = parts[0].lowercase()
            }
        }
        matchAndLookup(f, hashes, hashTargets, vtKey, bad)
        analyzeApps(f)
        step("Done.")
        return f
    }

    // -------------------------------------------------------------- NON-ROOT
    private fun runNonRoot(vtKey: String): List<Finding> {
        val f = mutableListOf<Finding>()
        val bad = loadBad()
        f += Finding("INFO", "Non-root mode",
            "Scanning shared storage and installed apps only. System partitions and other apps' private data are off-limits without root.")

        step("Listing files in shared storage…")
        val base = Environment.getExternalStorageDirectory()
        val files = base.walkTopDown().onFail { _, _ -> }.filter { it.isFile }.toList()
        val hashTargets = mutableListOf<File>()
        var elfChecks = 0
        files.forEachIndexed { i, file ->
            if (i % 500 == 0) step("Analyzing storage files $i/${files.size}…")
            val name = file.name
            val ext = name.substringAfterLast('.', "").lowercase()
            val p = file.absolutePath
            if (doubleExt.matches(name)) {
                f += Finding("HIGH", "Disguised double-extension file", p); hashTargets += file
            } else if (ext in riskyExt) {
                hashTargets += file
                if (ext == "apk") f += Finding("MEDIUM", "Installable APK sitting in storage", p)
                if (ext == "sh" || ext == "elf" || ext == "bin")
                    f += Finding("MEDIUM", "Executable/script in storage", p)
                if (ext == "sh" && file.length() < 1_000_000 &&
                    runCatching { scriptPattern.containsMatchIn(file.readText()) }.getOrDefault(false))
                    f += Finding("HIGH", "Script with reverse-shell/downloader pattern", p)
            } else if (ext.isEmpty() && elfChecks < 400) {
                elfChecks++
                val head = runCatching { file.inputStream().use { s -> ByteArray(4).also { s.read(it) } } }.getOrNull()
                if (head != null && head[0] == 0x7f.toByte() && head[1] == 'E'.code.toByte() &&
                    head[2] == 'L'.code.toByte() && head[3] == 'F'.code.toByte()) {
                    f += Finding("HIGH", "Disguised native executable (ELF)", p); hashTargets += file
                }
            }
            if (file.length() in 60L..200L &&
                runCatching { file.readText().contains(eicar) }.getOrDefault(false))
                f += Finding("HIGH", "EICAR test virus signature (scanner works)", p)
        }

        step("Collecting installed app packages…")
        @Suppress("DEPRECATION")
        val apks = ctx.packageManager.getInstalledPackages(0)
            .mapNotNull { it.applicationInfo?.sourceDir?.let { d -> File(d) } }

        val all = hashTargets + apks
        val hashes = LinkedHashMap<String, String>()
        all.forEachIndexed { i, file ->
            if (i % 10 == 0) step("Hashing files $i/${all.size}…")
            sha256(file)?.let { hashes[file.absolutePath] = it }
        }
        matchAndLookup(f, hashes, hashTargets.map { it.absolutePath }, vtKey, bad)
        analyzeApps(f)
        step("Done.")
        return f
    }

    // ---------------------------------------------------------------- SHARED
    private fun sha256(file: File): String? = try {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { s ->
            val buf = ByteArray(65536)
            while (true) { val n = s.read(buf); if (n < 0) break; md.update(buf, 0, n) }
        }
        md.digest().joinToString("") { "%02x".format(it) }
    } catch (e: Exception) { null }

    private fun matchAndLookup(
        f: MutableList<Finding>, hashes: Map<String, String>,
        targets: List<String>, vtKey: String, bad: Set<String>
    ) {
        hashes.forEach { (p, h) ->
            if (h in bad) f += Finding("CRITICAL", "Matches known-malware hash", "$p\nSHA-256: $h")
        }
        if (vtKey.isEmpty()) return
        val vtList = targets.mapNotNull { p -> hashes[p]?.let { p to it } }.take(20)
        vtList.forEachIndexed { i, (p, h) ->
            step("VirusTotal lookup ${i + 1}/${vtList.size}… (free tier = 4/min)")
            vtLookup(h, vtKey)?.let { n ->
                if (n > 0) f += Finding(if (n >= 5) "CRITICAL" else "HIGH",
                    "VirusTotal: $n engines flag this file", "$p\nSHA-256: $h")
            }
            Thread.sleep(16000)
        }
    }

    private fun analyzeApps(f: MutableList<Finding>) {
        step("Analyzing installed apps…")
        @Suppress("DEPRECATION")
        val pkgs = ctx.packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        for (pi in pkgs) {
            val ai = pi.applicationInfo ?: continue
            if (ai.flags and ApplicationInfo.FLAG_SYSTEM != 0) continue
            val perms = pi.requestedPermissions?.map { it.substringAfterLast('.') }?.toSet() ?: emptySet()
            @Suppress("DEPRECATION")
            val installer = ctx.packageManager.getInstallerPackageName(pi.packageName)
            val sideloaded = installer == null || installer == "com.google.android.packageinstaller"
            val label = "${ctx.packageManager.getApplicationLabel(ai)} (${pi.packageName})" +
                if (sideloaded) " [sideloaded]" else ""
            if ("SEND_SMS" in perms && "READ_CONTACTS" in perms)
                f += Finding(if (sideloaded) "HIGH" else "MEDIUM", "Can read contacts and send SMS (worm-style spreading)", label)
            if ("BIND_ACCESSIBILITY_SERVICE" in perms && "SYSTEM_ALERT_WINDOW" in perms)
                f += Finding(if (sideloaded) "HIGH" else "MEDIUM", "Accessibility + overlay (banking-trojan pattern)", label)
            if ("READ_SMS" in perms && "RECEIVE_SMS" in perms && "INTERNET" in perms && sideloaded)
                f += Finding("MEDIUM", "Sideloaded app that can read SMS and go online", label)
            if ("REQUEST_INSTALL_PACKAGES" in perms && sideloaded)
                f += Finding("MEDIUM", "Sideloaded app that can install other apps (dropper pattern)", label)
        }
    }

    private fun vtLookup(hash: String, key: String): Int? = try {
        val c = URL("https://www.virustotal.com/api/v3/files/$hash").openConnection() as HttpURLConnection
        c.setRequestProperty("x-apikey", key); c.connectTimeout = 10000; c.readTimeout = 10000
        if (c.responseCode == 200) {
            val body = c.inputStream.bufferedReader().readText()
            Regex("\"malicious\":\\s*(\\d+)").find(body)?.groupValues?.get(1)?.toInt()
        } else null
    } catch (e: Exception) { null }
}
