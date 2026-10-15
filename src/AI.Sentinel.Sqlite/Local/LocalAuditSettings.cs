namespace AI.Sentinel.Sqlite.Local;

/// <summary>Where a CLI records its audit entries, read from its environment by <see cref="LocalAudit.ReadSettings"/>.</summary>
/// <param name="DatabasePath">SQLite file to append to, or <see langword="null"/> when SQLite is off and the in-memory ring buffer is used.</param>
/// <param name="NdjsonPath">NDJSON file every entry is also forwarded to, or <see langword="null"/> for none.</param>
/// <param name="MaxDatabaseSizeBytes">Size cap for the SQLite file, or <see langword="null"/> for no cap.</param>
internal sealed record LocalAuditSettings(string? DatabasePath, string? NdjsonPath, long? MaxDatabaseSizeBytes);
