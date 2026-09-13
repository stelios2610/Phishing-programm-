package com.phishguard.scanner

import android.annotation.SuppressLint
import android.content.Intent
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.Charset
import javax.net.ssl.SSLException

class MainActivity : AppCompatActivity() {
    private lateinit var webView: WebView

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        webView = WebView(this)
        setContentView(webView)

        val settings = webView.settings
        settings.javaScriptEnabled = true
        settings.domStorageEnabled = true
        settings.allowFileAccess = true
        settings.allowContentAccess = true
        settings.cacheMode = WebSettings.LOAD_NO_CACHE
        settings.mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW

        webView.webChromeClient = WebChromeClient()
        webView.webViewClient = object : WebViewClient() {
            override fun onPageFinished(view: WebView?, url: String?) {
                consumeIncoming(intent)
            }
        }
        webView.addJavascriptInterface(Bridge(), "PhishGuardAndroid")
        webView.loadUrl("file:///android_asset/www/index.html")
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        consumeIncoming(intent)
    }

    private fun consumeIncoming(intent: Intent?) {
        if (intent == null) return
        val shared = when (intent.action) {
            Intent.ACTION_SEND -> intent.getStringExtra(Intent.EXTRA_TEXT)
            Intent.ACTION_VIEW -> intent.dataString
            Intent.ACTION_PROCESS_TEXT -> intent.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT)?.toString()
            else -> null
        } ?: return
        val escaped = JSONObject.quote(shared)
        webView.evaluateJavascript("window.phishguardSetUrl && window.phishguardSetUrl($escaped)", null)
    }

    inner class Bridge {
        @JavascriptInterface
        fun fetchHtml(rawUrl: String): String {
            val out = JSONObject()
            try {
                val url = URL(rawUrl)
                val conn = (url.openConnection() as HttpURLConnection).apply {
                    instanceFollowRedirects = true
                    connectTimeout = 8000
                    readTimeout = 8000
                    requestMethod = "GET"
                    setRequestProperty(
                        "User-Agent",
                        "PhishGuard/1.1 (phishing detector; read-only HTML)",
                    )
                }
                val code = conn.responseCode
                val stream = if (code >= 400) conn.errorStream else conn.inputStream
                val bytes = stream?.readBytes() ?: ByteArray(0)
                val slice = if (bytes.size > MAX_HTML) bytes.copyOf(MAX_HTML) else bytes
                out.put("status", code)
                out.put("html", String(slice, Charset.forName("UTF-8")))
                out.put("error", JSONObject.NULL)
            } catch (e: SSLException) {
                out.put("status", 0)
                out.put("html", "")
                out.put("error", "ssl:" + (e.message ?: "tls"))
            } catch (e: Exception) {
                out.put("status", 0)
                out.put("html", "")
                out.put("error", e.message ?: "fetch failed")
            }
            return out.toString()
        }
    }

    companion object {
        private const val MAX_HTML = 400_000
    }
}
