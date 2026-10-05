package com.example.rootscan

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.widget.*

class MainActivity : Activity() {
    private var report = ""

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        val pad = (16 * resources.displayMetrics.density).toInt()
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(pad, pad * 2, pad, pad) }
        val key = EditText(this).apply { hint = "VirusTotal API key (optional)"; isSingleLine = true }
        val nonRoot = CheckBox(this).apply { text = "Force non-root mode (skip root checks)" }
        val scan = Button(this).apply { text = "Scan device" }
        val share = Button(this).apply { text = "Share report"; isEnabled = false }
        val status = TextView(this).apply { text = "Ready. Uses root if available, otherwise non-root mode." }
        val results = TextView(this).apply {
            setTextIsSelectable(true); typeface = Typeface.MONOSPACE; textSize = 12f
        }
        col.addView(key); col.addView(nonRoot); col.addView(scan); col.addView(share); col.addView(status)
        col.addView(ScrollView(this).apply { addView(results) }, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(col)

        scan.setOnClickListener {
            scan.isEnabled = false; share.isEnabled = false; results.text = ""
            val force = nonRoot.isChecked
            Thread {
                val useRoot = !force && Root.available()
                if (!useRoot && !hasStorageAccess()) {
                    runOnUiThread {
                        status.text = "Grant storage access, then tap Scan again."
                        askStorageAccess(); scan.isEnabled = true
                    }
                    return@Thread
                }
                runOnUiThread { status.text = if (useRoot) "Root mode" else "Non-root mode" }
                val found = Scanner(this) { m -> runOnUiThread { status.text = m } }
                    .run(key.text.toString().trim(), useRoot)
                val order = listOf("CRITICAL", "HIGH", "ERROR", "MEDIUM", "INFO")
                val sorted = found.sortedBy { order.indexOf(it.severity) }
                report = if (sorted.isEmpty()) "No findings." else sorted.joinToString("\n\n") {
                    "[${it.severity}] ${it.title}\n${it.detail}"
                }
                runOnUiThread {
                    results.text = report
                    status.text = "Finished (${if (useRoot) "root" else "non-root"}): " +
                        "${found.count { it.severity in listOf("CRITICAL", "HIGH") }} high-risk, ${found.size} total"
                    scan.isEnabled = true; share.isEnabled = true
                }
            }.start()
        }
        share.setOnClickListener {
            startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"; putExtra(Intent.EXTRA_TEXT, report)
            }, "Share report"))
        }
    }

    private fun hasStorageAccess() =
        if (Build.VERSION.SDK_INT >= 30) Environment.isExternalStorageManager()
        else checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED

    private fun askStorageAccess() {
        if (Build.VERSION.SDK_INT >= 30) {
            startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                Uri.parse("package:$packageName")))
        } else {
            requestPermissions(arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE), 1)
        }
    }
}
