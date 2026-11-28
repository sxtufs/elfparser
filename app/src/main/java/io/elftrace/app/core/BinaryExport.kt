package io.elftrace.app.core

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import androidx.annotation.RequiresApi
import java.io.File
import java.io.FileOutputStream

/**
 * Writes a binary into the real public Download/ folder — no app-scoped copy and
 * no runtime permission. On API 29+ a MediaStore insert into the Downloads
 * collection needs zero permissions; on API < 29 (minSdk 24) the legacy public
 * directory plus WRITE_EXTERNAL_STORAGE is used.
 *
 * Shared by the app's own "save patched binary" and the MCP `save` tool, so both
 * land in the same place.
 */
object BinaryExport {
    /**
     * Returns the path shown to the user (`Download/<name>`). Throws when the
     * file could not be written.
     */
    fun toDownloads(context: Context, displayName: String, bytes: ByteArray): String {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return mediaStore(context, displayName, bytes)
        }
        val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        val file = File(dir, displayName)
        FileOutputStream(file).use { it.write(bytes) }
        return file.absolutePath
    }

    /**
     * Insert the bytes into the shared Download/ collection via MediaStore.
     * If a file with the same name already exists (owned by this app), it is
     * replaced so repeated exports don't accumulate duplicates.
     */
    @RequiresApi(Build.VERSION_CODES.Q)
    private fun mediaStore(context: Context, displayName: String, bytes: ByteArray): String {
        val resolver = context.contentResolver
        val collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI

        // Remove a previous export we own with the same display name.
        try {
            resolver.delete(
                collection,
                "${MediaStore.Downloads.DISPLAY_NAME} = ?",
                arrayOf(displayName)
            )
        } catch (_: Exception) {
        }

        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, displayName)
            put(MediaStore.Downloads.MIME_TYPE, "application/octet-stream")
            put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            put(MediaStore.Downloads.IS_PENDING, 1)
        }
        val uri = resolver.insert(collection, values)
            ?: throw IllegalStateException("MediaStore refused $displayName")
        resolver.openOutputStream(uri)?.use { os -> os.write(bytes) }
            ?: throw IllegalStateException("MediaStore gave no stream for $displayName")
        values.clear()
        values.put(MediaStore.Downloads.IS_PENDING, 0)
        resolver.update(uri, values, null, null)
        return "Download/$displayName"
    }
}
