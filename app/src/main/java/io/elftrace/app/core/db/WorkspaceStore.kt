package io.elftrace.app.core.db

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.Upsert
import java.io.File
import java.security.MessageDigest

/**
 * A binary the user has opened. The primary key is a content hash, not the
 * path: the file picker copies every ELF to `cacheDir/input_target.so`, so a
 * path key would mix the notes of every binary the user ever opened.
 */
@Entity(tableName = "sessions")
data class SessionRecord(
    @PrimaryKey val fileKey: String,
    val path: String,
    val displayName: String,
    val lastOpened: Long,
    val lastAddress: Long = 0L,
    val lastName: String = "",
)

@Entity(tableName = "renames", primaryKeys = ["fileKey", "address"])
data class RenameRecord(
    val fileKey: String,
    val address: Long,
    val name: String,
)

@Entity(tableName = "bookmarks")
data class BookmarkRecord(
    @PrimaryKey(autoGenerate = true) val id: Long = 0L,
    val fileKey: String,
    val address: Long,
    val name: String,
    val note: String = "",
    val created: Long = System.currentTimeMillis(),
)

/** One applied patch. The native undo stack lives in memory only; this is the
 *  durable copy that lets a patch survive closing the binary. */
@Entity(tableName = "journal")
data class JournalRecord(
    @PrimaryKey(autoGenerate = true) val id: Long = 0L,
    val fileKey: String,
    val address: Long,
    val kind: String,
    val original: ByteArray,
    val patched: ByteArray,
    val created: Long = System.currentTimeMillis(),
) {
    override fun equals(other: Any?): Boolean = other is JournalRecord && other.id == id

    override fun hashCode(): Int = id.toInt()
}

@Dao
interface WorkspaceDao {
    @Upsert
    suspend fun upsertSession(session: SessionRecord)

    @Query("DELETE FROM sessions WHERE fileKey NOT IN (SELECT fileKey FROM sessions ORDER BY lastOpened DESC LIMIT 10)")
    suspend fun trimSessions()

    @Query("UPDATE sessions SET lastAddress = :address, lastName = :name WHERE fileKey = :fileKey")
    suspend fun savePosition(fileKey: String, address: Long, name: String)

    @Query("SELECT * FROM sessions ORDER BY lastOpened DESC LIMIT :limit")
    suspend fun recentSessions(limit: Int = 5): List<SessionRecord>

    @Query("DELETE FROM sessions WHERE fileKey = :fileKey")
    suspend fun forgetSession(fileKey: String)

    @Upsert
    suspend fun saveRename(rename: RenameRecord)

    @Query("SELECT * FROM renames WHERE fileKey = :fileKey ORDER BY address")
    suspend fun renames(fileKey: String): List<RenameRecord>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun addBookmark(bookmark: BookmarkRecord): Long

    @Query("DELETE FROM bookmarks WHERE fileKey = :fileKey AND address = :address")
    suspend fun removeBookmark(fileKey: String, address: Long)

    @Query("SELECT * FROM bookmarks WHERE fileKey = :fileKey ORDER BY address")
    suspend fun bookmarks(fileKey: String): List<BookmarkRecord>

    @Insert
    suspend fun appendJournal(entry: JournalRecord)

    @Query("DELETE FROM journal WHERE id = (SELECT id FROM journal WHERE fileKey = :fileKey AND address = :address ORDER BY id DESC LIMIT 1)")
    suspend fun removeLatestJournalAt(fileKey: String, address: Long)

    @Query("SELECT * FROM journal WHERE fileKey = :fileKey ORDER BY id")
    suspend fun journal(fileKey: String): List<JournalRecord>

    @Query("DELETE FROM journal WHERE fileKey = :fileKey")
    suspend fun clearJournal(fileKey: String)
}

@Database(
    entities = [SessionRecord::class, RenameRecord::class, BookmarkRecord::class, JournalRecord::class],
    version = 1,
    exportSchema = false
)
abstract class WorkspaceDatabase : RoomDatabase() {
    abstract fun dao(): WorkspaceDao
}

/**
 * The app's workspace: recent files, last position per binary, renames,
 * bookmarks and the patch journal.
 *
 * Every method suspends; callers use the ViewModel's single native dispatcher
 * so database work never runs on the main thread.
 */
class WorkspaceStore private constructor(private val db: WorkspaceDatabase) {

    companion object {
        fun create(context: Context): WorkspaceStore = WorkspaceStore(
            Room.databaseBuilder(
                context.applicationContext,
                WorkspaceDatabase::class.java,
                "elftrace_workspace.db"
            ).build()
        )

        /** SHA-256 of the file contents, hex encoded. */
        fun fileKey(file: File): String {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buf = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    digest.update(buf, 0, n)
                }
            }
            return digest.digest().joinToString("") { "%02x".format(it) }
        }
    }

    suspend fun touchSession(fileKey: String, path: String, displayName: String) {
        val existing = db.dao().recentSessions(10).firstOrNull { it.fileKey == fileKey }
        db.dao().upsertSession(
            (existing ?: SessionRecord(fileKey, path, displayName, 0L)).copy(
                path = path,
                displayName = displayName,
                lastOpened = System.currentTimeMillis()
            )
        )
        db.dao().trimSessions()
    }

    suspend fun savePosition(fileKey: String, address: Long, name: String) =
        db.dao().savePosition(fileKey, address, name)

    suspend fun recentSessions(limit: Int = 5): List<SessionRecord> = db.dao().recentSessions(limit)

    suspend fun forgetSession(fileKey: String) = db.dao().forgetSession(fileKey)

    suspend fun saveRename(fileKey: String, address: Long, name: String) =
        db.dao().saveRename(RenameRecord(fileKey, address, name))

    suspend fun renames(fileKey: String): List<RenameRecord> = db.dao().renames(fileKey)

    suspend fun addBookmark(fileKey: String, address: Long, name: String, note: String = "") =
        db.dao().addBookmark(BookmarkRecord(fileKey = fileKey, address = address, name = name, note = note))

    suspend fun removeBookmark(fileKey: String, address: Long) =
        db.dao().removeBookmark(fileKey, address)

    suspend fun bookmarks(fileKey: String): List<BookmarkRecord> = db.dao().bookmarks(fileKey)

    suspend fun appendJournal(
        fileKey: String,
        address: Long,
        kind: String,
        original: ByteArray,
        patched: ByteArray
    ) = db.dao().appendJournal(
        JournalRecord(fileKey = fileKey, address = address, kind = kind, original = original, patched = patched)
    )

    suspend fun removeLatestJournalAt(fileKey: String, address: Long) =
        db.dao().removeLatestJournalAt(fileKey, address)

    suspend fun journal(fileKey: String): List<JournalRecord> = db.dao().journal(fileKey)

    suspend fun clearJournal(fileKey: String) = db.dao().clearJournal(fileKey)

    fun close() = db.close()
}
