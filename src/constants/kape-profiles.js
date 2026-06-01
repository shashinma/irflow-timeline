export const KAPE_PROFILES = {
  // ── EZ Tools ────────────────────────────────────────────────────
  "MFTECmd ($MFT)": {
    detect: ["EntryNumber", "SequenceNumber", "ParentPath", "FileName", "Created0x10"],
    pinnedColumns: ["FileName", "ParentPath"],
    hiddenColumns: ["UpdateSequenceNumber", "LogfileSequenceNumber", "SecurityId", "NameType", "LoggedUtilStream", "SequenceNumber", "InUse", "ParentSequenceNumber", "ParentEntryNumber", "IsAds", "SiFlags", "FnAttributeId", "OtherAttributeId", "ReferenceCount"],
    columnOrder: ["EntryNumber", "ParentPath", "FileName", "Extension", "IsDirectory", "HasAds", "FileSize", "Created0x10", "Created0x30", "LastModified0x10", "LastModified0x30", "LastRecordChange0x10", "LastAccess0x10", "ZoneIdContents", "Timestomped", "uSecZeros", "Copied"],
  },
  "EvtxECmd (EVTX)": {
    detect: ["RecordNumber", "TimeCreated", "EventId", "Provider", "Channel"],
    pinnedColumns: ["TimeCreated", "EventId"],
    hiddenColumns: ["ChunkNumber", "ExtraDataOffset", "HiddenRecord", "ProcessId", "ThreadId"],
    columnOrder: ["RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level", "Provider", "Channel", "Computer", "UserId", "MapDescription", "UserName", "RemoteHost", "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6", "ExecutableInfo", "SourceFile", "Payload", "Keywords"],
  },
  "PECmd (Prefetch)": {
    detect: ["ExecutableName", "RunCount", "LastRun", "Volume0Name", "Hash"],
    pinnedColumns: ["ExecutableName", "LastRun"],
    hiddenColumns: ["FileSize", "ParsingError"],
    columnOrder: ["SourceFilename", "SourceCreated", "SourceModified", "SourceAccessed", "ExecutableName", "RunCount", "Hash", "Size", "Version", "LastRun", "PreviousRun0", "PreviousRun1", "PreviousRun2", "PreviousRun3", "Volume0Name", "Volume0Serial", "Volume0Created", "Directories", "FilesLoaded"],
  },
  "LECmd (LNK)": {
    detect: ["SourceFile", "TargetIDAbsolutePath", "HeaderFlags", "DriveType"],
    pinnedColumns: ["SourceFile"],
    columnOrder: ["SourceFile", "SourceCreated", "SourceModified", "SourceAccessed", "TargetCreated", "TargetModified", "TargetAccessed", "FileSize", "RelativePath", "WorkingDirectory", "FileAttributes", "HeaderFlags", "LocalPath", "CommonPath", "Arguments", "TargetIDAbsolutePath", "TargetMFTEntryNumber", "MachineID", "MachineMACAddress", "TrackerCreatedOn"],
  },
  "AmcacheParser (Files)": {
    detect: ["ApplicationName", "ProgramId", "FileKeyLastWriteTimestamp", "SHA1"],
    pinnedColumns: ["ApplicationName", "FullPath"],
    hiddenColumns: ["Language", "Usn", "LongPathHash", "BinaryType"],
    columnOrder: ["ApplicationName", "ProgramId", "FileKeyLastWriteTimestamp", "SHA1", "IsOsComponent", "FullPath", "Name", "FileExtension", "LinkDate", "ProductName", "Size", "Version", "ProductVersion", "IsPeFile", "BinFileVersion"],
  },
  "AmcacheParser (Programs)": {
    detect: ["ProgramId", "KeyLastWriteTimestamp", "Publisher", "InstallDate"],
    pinnedColumns: ["ProgramId", "Name"],
    columnOrder: ["ProgramId", "KeyLastWriteTimestamp", "Name", "Version", "Publisher", "InstallDate", "OSVersionAtInstallTime", "BundleManifestPath", "HiddenArp", "InboxModernApp", "MsiPackageCode", "MsiProductCode", "PackageFullName", "RegistryKeyPath", "RootDirPath", "Type", "Source", "UninstallString"],
  },
  "RECmd (Registry)": {
    detect: ["HivePath", "KeyPath", "ValueName", "ValueType", "ValueData"],
    pinnedColumns: ["KeyPath", "ValueName"],
    columnOrder: ["HivePath", "KeyPath", "ValueName", "ValueType", "ValueData", "ValueData2", "ValueData3", "LastWriteTimestamp", "Description", "Category"],
  },
  "SBECmd (ShellBags)": {
    detect: ["AbsolutePath", "BagPath", "ShellType", "Value"],
    pinnedColumns: ["AbsolutePath", "ShellType"],
    columnOrder: ["BagPath", "Slot", "NodeSlot", "MRUPosition", "AbsolutePath", "ShellType", "Value", "ChildBags", "CreatedOn", "ModifiedOn", "AccessedOn", "LastWriteTime", "FirstInteracted", "LastInteracted", "HasExplored"],
  },
  "SrumECmd (SRUM)": {
    detect: ["Timestamp", "ExeInfo", "SidType", "Sid"],
    pinnedColumns: ["Timestamp", "ExeInfo"],
    columnOrder: ["Timestamp", "ExeInfo", "SidType", "Sid", "UserName"],
  },
  "AppCompatcache (Shimcache)": {
    detect: ["ControlSet", "CacheEntryPosition", "Path", "LastModifiedTimeUTC", "Executed"],
    pinnedColumns: ["Path", "Executed"],
    hiddenColumns: ["FileSize"],
    columnOrder: ["ControlSet", "Duplicate", "CacheEntryPosition", "Executed", "LastModifiedTimeUTC", "Path", "SourceFile"],
  },
  "JLECmd (Auto Jump Lists)": {
    detect: ["AppId", "AppIdDescription", "EntryName", "TargetIDAbsolutePath"],
    pinnedColumns: ["AppId", "AppIdDescription"],
    columnOrder: ["SourceFile", "SourceCreated", "SourceModified", "SourceAccessed", "AppId", "AppIdDescription", "EntryName", "TargetCreated", "TargetModified", "TargetAccessed", "FileSize", "RelativePath", "WorkingDirectory", "LocalPath", "CommonPath", "Arguments", "TargetIDAbsolutePath", "MachineID", "MachineMACAddress", "TrackerCreatedOn", "InteractionCount"],
  },
  // ── Timeline Formats ────────────────────────────────────────────
  "ForensicTimeline": {
    detect: ["DateTime", "TimestampInfo", "ArtifactName", "Tool", "Description"],
    pinnedColumns: ["DateTime", "ArtifactName"],
    columnOrder: ["DateTime", "TimestampInfo", "ArtifactName", "Tool", "Description", "DataDetails", "DataPath", "FileExtension", "EvidencePath", "EventId", "User", "Computer", "FileSize", "IPAddress", "SourceAddress", "DestinationAddress", "SHA1", "Count", "RawData"],
    autoColorColumn: "ArtifactName",
  },
  "SuperTimeline (Plaso)": {
    detect: ["date", "time", "macb", "source", "sourcetype", "type"],
    pinnedColumns: ["date", "sourcetype"],
    columnOrder: ["date", "time", "macb", "source", "sourcetype", "type", "user", "host", "short", "desc", "filename", "inode", "notes", "format", "extra"],
    autoColorColumn: "source",
  },
  "MacTime": {
    detect: ["Timestamp", "Macb", "SourceName", "LongDescription", "FileName"],
    pinnedColumns: ["Timestamp", "FileName"],
    hiddenColumns: ["TimeZone", "Type", "Username", "HostName", "ShortDescription", "Version", "Notes", "Format", "Extra"],
    columnOrder: ["Timestamp", "SourceDescription", "SourceName", "Macb", "LongDescription", "Inode", "FileName"],
    autoColorColumn: "SourceName",
  },
  "KapeMiniTimeline": {
    detect: ["Timestamp", "DataType", "ComputerName", "UserSource", "Message"],
    pinnedColumns: ["Timestamp", "Message"],
    columnOrder: ["Timestamp", "DataType", "ComputerName", "UserSource", "Message"],
    autoColorColumn: "DataType",
  },
  "PsortTimeline (Plaso)": {
    detect: ["Timestamp", "TimestampDescription", "Source", "SourceLong"],
    pinnedColumns: ["Timestamp", "DisplayName"],
    columnOrder: ["Timestamp", "TimestampDescription", "Source", "SourceLong", "Message", "Parser", "DisplayName", "TagInfo"],
    autoColorColumn: "Source",
  },
  // ── Misc Tools ──────────────────────────────────────────────────
  "Hayabusa (Standard)": {
    detect: ["Timestamp", "RuleTitle", "Level", "Channel", "EventId", "RecordId", "Details"],
    pinnedColumns: ["Timestamp", "RuleTitle"],
    columnOrder: ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventId", "RecordId", "Details", "ExtraFieldInfo"],
    autoColorColumn: "Level",
  },
  "Hayabusa (Verbose)": {
    detect: ["Timestamp", "RuleTitle", "Level", "MitreTactics", "MitreTags", "OtherTags"],
    pinnedColumns: ["Timestamp", "RuleTitle"],
    columnOrder: ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventId", "MitreTactics", "MitreTags", "OtherTags", "RecordId", "Details", "ExtraFieldInfo", "RuleFile", "EvtxFile"],
    autoColorColumn: "Level",
  },
  "Chainsaw (Logons)": {
    detect: ["system_time", "id", "workstation_name", "target_username", "source_ip", "logon_type"],
    pinnedColumns: ["system_time", "target_username"],
    columnOrder: ["system_time", "id", "target_username", "source_ip", "workstation_name", "logon_type"],
    autoColorColumn: "logon_type",
  },
  "Chainsaw (Command Line Hunt)": {
    detect: ["system_time", "id", "detection_rules", "computer_name", "Event.EventData.CommandLine", "process_name"],
    pinnedColumns: ["system_time", "detection_rules"],
    columnOrder: ["system_time", "id", "detection_rules", "computer_name", "process_name", "Event.EventData.CommandLine"],
    autoColorColumn: "detection_rules",
  },
  "Chainsaw (Process Creation Hunt)": {
    detect: ["system_time", "id", "detection_rules", "computer_name", "Event.EventData.Image", "command_line"],
    pinnedColumns: ["system_time", "detection_rules"],
    columnOrder: ["system_time", "id", "detection_rules", "computer_name", "Event.EventData.Image", "command_line"],
    autoColorColumn: "detection_rules",
  },
  "Chainsaw (Registry Hunt)": {
    detect: ["system_time", "id", "detection_rules", "computer_name", "Event.EventData.Details", "target_object"],
    pinnedColumns: ["system_time", "target_object"],
    columnOrder: ["system_time", "id", "detection_rules", "computer_name", "target_object", "Event.EventData.Details"],
    autoColorColumn: "detection_rules",
  },
  "Chainsaw (File Creation Hunt)": {
    detect: ["system_time", "id", "detection_rules", "computer_name", "Event.EventData.TargetFilename", "image"],
    pinnedColumns: ["system_time", "Event.EventData.TargetFilename"],
    columnOrder: ["system_time", "id", "detection_rules", "computer_name", "Event.EventData.TargetFilename", "image"],
    autoColorColumn: "detection_rules",
  },
  "Chainsaw (Sigma)": {
    detect: ["Timestamp", "RuleTitle", "Level", "Channel", "MitreTactics"],
    pinnedColumns: ["Timestamp", "RuleTitle"],
    columnOrder: ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventId", "MitreTactics", "MitreTags", "OtherTags", "RecordId", "Details", "ExtraFieldInfo", "RuleFile", "EvtxFile"],
    autoColorColumn: "Level",
  },
  "BrowsingHistoryView": {
    detect: ["Url", "Title", "VisitTimeUtc", "WebBrowser", "UserProfile"],
    pinnedColumns: ["Url", "Title"],
    columnOrder: ["Url", "Title", "VisitTimeUtc", "VisitCount", "VisitedFrom", "VisitType", "WebBrowser", "UserProfile", "BrowserProfile", "UrlLength", "TypedCount", "HistoryFile"],
  },
  "KAPE Copy Log": {
    detect: ["CopiedTimestamp", "SourceFile", "DestinationFile", "SourceFileSha1"],
    pinnedColumns: ["SourceFile", "DestinationFile"],
    columnOrder: ["CopiedTimestamp", "SourceFile", "DestinationFile", "FileSize", "SourceFileSha1", "DeferredCopy", "CreatedOnUtc", "ModifiedOnUtc", "LastAccessedOnUtc", "CopyDuration"],
  },
};
