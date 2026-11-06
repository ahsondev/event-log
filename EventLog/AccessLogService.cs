using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Xml;
using System.Xml.Linq;

namespace EventLog
{
    public static class AccessLogService
    {
        const int ScanLimit = 20000;
        const int SshTailBytes = 2 * 1024 * 1024;

        static readonly string[] Months =
        {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        };

        static readonly string[] SshChannels =
        {
            "OpenSSH/Operational",
            "OpenSSH/Admin",
            "Microsoft-Windows-OpenSSH/Operational",
            "Microsoft-Windows-OpenSSH/Admin"
        };

        static readonly Regex IsoTime = new Regex(
            @"(?<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)",
            RegexOptions.Compiled);

        static readonly Regex SyslogTime = new Regex(
            @"\b(?<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?<day>\d{1,2})\s+(?<time>\d{2}:\d{2}:\d{2})\b",
            RegexOptions.Compiled);

        static readonly Regex SshAccepted = new Regex(
            @"Accepted\s+(?<method>\S+)\s+for\s+(?<user>\S+)\s+from\s+(?<ip>\S+)\s+port\s+(?<port>\d+)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        static readonly Regex SshFailed = new Regex(
            @"Failed\s+(?<method>\S+)\s+for\s+(?:invalid user\s+)?(?<user>\S+)\s+from\s+(?<ip>\S+)\s+port\s+(?<port>\d+)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        static readonly Regex SshInvalid = new Regex(
            @"Invalid user\s+(?<user>\S+)\s+from\s+(?<ip>\S+)(?:\s+port\s+(?<port>\d+))?",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        static readonly Regex SshConnect = new Regex(
            @"Connection from\s+(?<ip>\S+)\s+port\s+(?<port>\d+)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        static readonly Regex SshClosed = new Regex(
            @"Disconnected from (?:user )?(?<user>\S+ )?(?<ip>\S+) port (?<port>\d+)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        static readonly Regex EndpointInText = new Regex(
            @"\b(?<ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?<port>\d{1,5}))?\b",
            RegexOptions.Compiled);

        static readonly Regex SshConnectionClosed = new Regex(
            @"Connection closed by (?:authenticating user )?(?<user>\S+ )?(?<ip>\S+) port (?<port>\d+)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public static AccessLogResult Load(AccessQuery query, IProgress<string> progress, CancellationToken cancellationToken)
        {
            if (query == null) throw new ArgumentNullException("query");

            int maxEvents = query.MaxEvents;
            if (maxEvents < 1) maxEvents = 1;
            if (maxEvents > 50000) maxEvents = 50000;

            int hours = query.Hours;
            if (hours < 1) hours = 1;
            if (hours > 8760) hours = 8760;

            var result = new AccessLogResult();
            var noteSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var seenEvents = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var seenErrors = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            string computer = (query.Computer ?? "").Trim().TrimStart('\\');
            bool local = IsLocalComputer(computer);
            result.Computer = local ? Environment.MachineName : computer;

            var sinceUtc = DateTime.UtcNow.AddHours(-hours);
            string timeClause = TimeClause(sinceUtc);
            var reads = BuildReads(query, timeClause);

            bool sshChannelOpened = false;
            int sshFileEvents = 0;
            bool securityDenied = false;

            EventLogSession session = null;
            bool disposeSession = false;
            try
            {
                if (local)
                {
                    session = EventLogSession.GlobalSession;
                }
                else
                {
                    progress?.Report("Connecting to " + computer + "...");
                    session = new EventLogSession(computer);
                    disposeSession = true;
                }

                foreach (var read in reads)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (securityDenied && read.LogName == "Security")
                        continue;
                    progress?.Report("Reading " + read.Display + "...");

                    string error;
                    var status = ReadChannel(
                        session,
                        read,
                        maxEvents,
                        query.ServiceAccounts,
                        result,
                        seenEvents,
                        progress,
                        cancellationToken,
                        out error);

                    if (status == ChannelOpen.Read && read.Kind == ChannelKind.SshLog)
                        sshChannelOpened = true;

                    if (status == ChannelOpen.Missing)
                    {
                        if (read.LogName == "Security")
                            AddNote(result, noteSet, "Security log was not found.");
                        else if (read.LogName == "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational")
                            AddNote(result, noteSet, "Remote Desktop connection log was not found.");
                        else if (read.LogName == "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational")
                            AddNote(result, noteSet, "Remote Desktop session log was not found.");
                        else if (read.LogName == "Microsoft-Windows-TerminalServices-RDPClient/Operational")
                            AddNote(result, noteSet, "Outbound Remote Desktop log was not found.");
                        else if (read.LogName == "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational")
                            AddNote(result, noteSet, "Remote Desktop client-address log was not found.");
                        else if (read.LogName == "Microsoft-Windows-SMBServer/Security")
                            AddNote(result, noteSet, "SMB sign-in log was not found, so file-share attempts cannot be named.");
                    }
                    else if (status == ChannelOpen.Failed)
                    {
                        if (read.LogName == "Security" && IsAccessDenied(error))
                            securityDenied = true;
                        if (seenErrors.Add(error ?? ""))
                            AddNote(result, noteSet, DescribeFailure(read, error));
                        if (IsConnectionFailure(error))
                            break;
                    }
                }

                if (local && query.Ssh)
                {
                    progress?.Report("Reading sshd.log...");
                    sshFileEvents = ReadSshFiles(sinceUtc, maxEvents, result, seenEvents, noteSet, cancellationToken);
                }
                else if (!local && query.Ssh && !sshChannelOpened)
                {
                    AddNote(result, noteSet, "sshd.log is only read on the server itself. The OpenSSH event log was queried remotely.");
                }
            }
            finally
            {
                if (disposeSession && session != null)
                    session.Dispose();
            }

            if (query.Ssh && !sshChannelOpened && sshFileEvents == 0 && local)
                AddNote(result, noteSet, "No OpenSSH event log or sshd.log was found.");

            if (result.Events.Count == 0)
                AddNote(result, noteSet, "No matching access events in this range.");

            DropUnaddressedListenerEvents(result);
            MergeSmbAttempts(result);
            result.Events.Sort((a, b) => b.Time.CompareTo(a.Time));
            return result;
        }

        static List<LogRead> BuildReads(AccessQuery query, string timeClause)
        {
            var reads = new List<LogRead>();

            if (query.Rdp)
            {
                reads.Add(Security("Remote Desktop sign-ins", WithTypes(timeClause, new[] { 4624 }, 10, 12)));
                reads.Add(Security("Remote Desktop failures", WithTypes(timeClause, new[] { 4625 }, 10, 12)));
                reads.Add(new LogRead(
                    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
                    "Remote Desktop connections",
                    "RDP connection",
                    SystemIds(timeClause, 1149, 261),
                    ChannelKind.RemoteDesktop,
                    true,
                    false));
                reads.Add(new LogRead(
                    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
                    "Remote Desktop client addresses",
                    "RDP connection",
                    SystemIds(timeClause, 131),
                    ChannelKind.RemoteDesktop,
                    true,
                    false));
                reads.Add(new LogRead(
                    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                    "Remote Desktop sessions",
                    "RDP session",
                    SystemIds(timeClause, 21, 22, 23, 24, 25, 39, 40),
                    ChannelKind.RemoteDesktop,
                    true,
                    false));
                reads.Add(new LogRead(
                    "Microsoft-Windows-TerminalServices-RDPClient/Operational",
                    "Outbound Remote Desktop",
                    "RDP client",
                    SystemIds(timeClause, 1024, 1025, 1026, 1027),
                    ChannelKind.RdpClient,
                    true,
                    false));
                reads.Add(new LogRead(
                    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin",
                    "Remote Desktop errors",
                    "RDP admin",
                    TimeOnly(timeClause),
                    ChannelKind.RemoteDesktop,
                    true,
                    true));
                reads.Add(new LogRead(
                    "Microsoft-Windows-TerminalServices-Gateway/Operational",
                    "RD Gateway",
                    "RD Gateway",
                    TimeOnly(timeClause),
                    ChannelKind.Gateway,
                    true,
                    false));
            }

            if (query.Ssh)
            {
                reads.Add(Security("SSH sign-ins", WithSshProcess(timeClause, 4624, 4625)));
                foreach (var channel in SshChannels)
                {
                    reads.Add(new LogRead(
                        channel,
                        "OpenSSH",
                        "OpenSSH",
                        TimeOnly(timeClause),
                        ChannelKind.SshLog,
                        true,
                        false));
                }
            }

            if (query.Console)
            {
                reads.Add(Security("Console sign-ins", WithTypes(timeClause, new[] { 4624 }, 2, 7, 9, 11, 13)));
                reads.Add(Security("Console failures", WithTypes(timeClause, new[] { 4625 }, 2, 7, 9, 11, 13)));
            }

            if (query.Network)
            {
                reads.Add(Security("Network sign-ins", WithTypes(timeClause, new[] { 4624 }, 3, 8)));
                reads.Add(Security("Network failures", WithTypes(timeClause, new[] { 4625 }, 3, 8)));
                reads.Add(Security("File share access", SystemIds(timeClause, 5140, 5145)));
            }

            if (query.Network || query.Failures)
            {
                reads.Add(new LogRead(
                    "Microsoft-Windows-SMBServer/Security",
                    "SMB sign-ins",
                    "SMB",
                    SystemIds(timeClause, 551),
                    ChannelKind.Smb,
                    true,
                    false));
            }

            if (query.Failures)
                reads.Add(Security("Failed logons", SystemIds(timeClause, 4625)));

            if (query.SignOut)
                reads.Add(Security("Sign-outs", SystemIds(timeClause, 4647, 4778, 4779)));

            if (query.ServiceAccounts)
            {
                reads.Add(Security("Service sign-ins", WithTypes(timeClause, new[] { 4624 }, 4, 5)));
                reads.Add(Security("Service failures", WithTypes(timeClause, new[] { 4625 }, 4, 5)));
            }

            return reads;
        }

        static LogRead Security(string display, string xpath)
        {
            return new LogRead("Security", display, "Security", xpath, ChannelKind.Security, false, false);
        }

        static ChannelOpen ReadChannel(
            EventLogSession session,
            LogRead read,
            int maxEvents,
            bool keepNoise,
            AccessLogResult result,
            HashSet<string> seenEvents,
            IProgress<string> progress,
            CancellationToken cancellationToken,
            out string error)
        {
            error = null;
            EventLogReader reader = null;
            try
            {
                var eventQuery = new EventLogQuery(read.LogName, PathType.LogName, read.XPath)
                {
                    Session = session,
                    ReverseDirection = true,
                    TolerateQueryErrors = false
                };
                reader = new EventLogReader(eventQuery);

                int scanned = 0;
                int kept = 0;
                for (;;)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    EventRecord record;
                    try
                    {
                        record = reader.ReadEvent();
                    }
                    catch (EventLogNotFoundException)
                    {
                        throw;
                    }
                    catch (EventLogException ex)
                    {
                        error = ex.Message;
                        if (scanned > 0 || kept > 0)
                        {
                            result.Notes.Add(read.Display + " stopped early: " + ex.Message);
                            return ChannelOpen.Read;
                        }
                        return ChannelOpen.Failed;
                    }

                    if (record == null)
                        break;

                    using (record)
                    {
                        scanned++;
                        if (read.WarningsOnly)
                        {
                            byte level = record.Level ?? 2;
                            if (level >= 4)
                            {
                                if (scanned >= ScanLimit)
                                {
                                    MarkTruncated(result, read, kept, maxEvents);
                                    break;
                                }
                                continue;
                            }
                        }

                        if (scanned % 400 == 0)
                            progress?.Report("Reading " + read.Display + " (" + scanned.ToString("N0") + " scanned)...");

                        var fields = ReadFields(record);
                        string formatted = null;
                        if (read.Kind != ChannelKind.Security)
                            formatted = FormatMessage(record);

                        var ev = Map(read, record, fields, formatted, keepNoise);
                        if (ev == null)
                        {
                            if (scanned >= ScanLimit)
                            {
                                MarkTruncated(result, read, kept, maxEvents);
                                break;
                            }
                            continue;
                        }

                        if (read.Kind == ChannelKind.Security)
                            ev.Message = BuildMessage(record, FormatMessage(record), fields);

                        if (string.IsNullOrEmpty(ev.Summary))
                            ev.Summary = OneLine(formatted ?? "", 180);
                        if (string.IsNullOrEmpty(ev.Summary))
                            ev.Summary = read.Display;

                        if (!seenEvents.Add(DedupeKey(ev)))
                            continue;

                        result.Events.Add(ev);
                        kept++;
                        if (kept >= maxEvents || scanned >= ScanLimit)
                        {
                            MarkTruncated(result, read, kept, maxEvents);
                            break;
                        }
                    }
                }

                return ChannelOpen.Read;
            }
            catch (EventLogNotFoundException)
            {
                return ChannelOpen.Missing;
            }
            catch (UnauthorizedAccessException ex)
            {
                error = ex.Message;
                return ChannelOpen.Failed;
            }
            catch (EventLogException ex)
            {
                error = ex.Message;
                return ChannelOpen.Failed;
            }
            finally
            {
                if (reader != null)
                    reader.Dispose();
            }
        }

        static void MarkTruncated(AccessLogResult result, LogRead read, int kept, int maxEvents)
        {
            result.Truncated = true;
            if (kept >= maxEvents)
                result.Notes.Add(read.Display + " reached the limit of " + maxEvents.ToString("N0") + " events.");
            else
                result.Notes.Add(read.Display + " is still verbose after scanning " + ScanLimit.ToString("N0") + " entries.");
        }

        static int ReadSshFiles(
            DateTime sinceUtc,
            int maxEvents,
            AccessLogResult result,
            HashSet<string> seenEvents,
            HashSet<string> noteSet,
            CancellationToken cancellationToken)
        {
            int keptTotal = 0;
            foreach (var path in SshLogFiles())
            {
                cancellationToken.ThrowIfCancellationRequested();
                bool truncatedFile;
                string text;
                try
                {
                    text = ReadTail(path, SshTailBytes, out truncatedFile);
                }
                catch (Exception ex)
                {
                    AddNote(result, noteSet, Path.GetFileName(path) + ": " + ex.Message);
                    continue;
                }

                if (truncatedFile)
                    AddNote(result, noteSet, "Only the last 2 MB of " + path + " was read.");

                int kept = 0;
                int accessLines = 0;
                int recognized = 0;
                int lineNumber = 0;
                using (var reader = new StringReader(text))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        lineNumber++;
                        cancellationToken.ThrowIfCancellationRequested();
                        if (line.Length == 0 || !IsSshAccessLine(line))
                            continue;
                        accessLines++;
                        var stamp = TryParseTimestamp(line);
                        if (!stamp.HasValue)
                            continue;
                        if (stamp.Value < sinceUtc)
                            continue;
                        recognized++;

                        var ev = FromSshText(line.Trim(), stamp.Value.ToLocalTime(), path, "sshd.log", 0, lineNumber);
                        if (!seenEvents.Add(DedupeKey(ev)))
                            continue;
                        result.Events.Add(ev);
                        kept++;
                        keptTotal++;
                        if (kept >= maxEvents)
                        {
                            result.Truncated = true;
                            AddNote(result, noteSet, Path.GetFileName(path) + " reached the limit of " + maxEvents.ToString("N0") + " events.");
                            break;
                        }
                    }
                }

                if (accessLines > 0 && recognized == 0)
                    AddNote(result, noteSet, path + " has SSH lines, but their timestamps were not recognized.");
            }

            return keptTotal;
        }

        static IEnumerable<string> SshLogFiles()
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string[] seeds =
            {
                @"C:\ProgramData\ssh\logs\sshd.log",
                @"C:\ProgramData\ssh\sshd.log",
                @"C:\Windows\System32\OpenSSH\logs\sshd.log",
                @"C:\Windows\System32\OpenSSH\sshd.log"
            };
            foreach (var file in seeds)
            {
                if (File.Exists(file) && seen.Add(file))
                    yield return file;
            }

            string[] folders =
            {
                @"C:\ProgramData\ssh\logs",
                @"C:\Windows\System32\OpenSSH\logs"
            };
            foreach (var folder in folders)
            {
                if (!Directory.Exists(folder))
                    continue;
                string[] found;
                try
                {
                    found = Directory.GetFiles(folder, "*.log");
                }
                catch (IOException)
                {
                    continue;
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var file in found)
                {
                    if (seen.Add(file))
                        yield return file;
                }
            }
        }

        static string ReadTail(string path, int maxBytes, out bool truncated)
        {
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                long start = 0;
                truncated = stream.Length > maxBytes;
                if (truncated)
                    start = stream.Length - maxBytes;
                stream.Seek(start, SeekOrigin.Begin);
                using (var reader = new StreamReader(stream, Encoding.UTF8, true))
                {
                    var text = reader.ReadToEnd();
                    if (start > 0)
                    {
                        int newline = text.IndexOf('\n');
                        if (newline >= 0 && newline < text.Length - 1)
                            text = text.Substring(newline + 1);
                    }
                    return text;
                }
            }
        }

        static bool IsSshAccessLine(string line)
        {
            if (SshAccepted.IsMatch(line) || SshFailed.IsMatch(line) || SshInvalid.IsMatch(line) ||
                SshConnect.IsMatch(line) || SshClosed.IsMatch(line) || SshConnectionClosed.IsMatch(line))
                return true;
            if (line.IndexOf("debug", StringComparison.OrdinalIgnoreCase) >= 0)
                return false;
            return line.IndexOf("Accepted", StringComparison.OrdinalIgnoreCase) >= 0
                || line.IndexOf("Failed", StringComparison.OrdinalIgnoreCase) >= 0
                || line.IndexOf("Invalid user", StringComparison.OrdinalIgnoreCase) >= 0
                || line.IndexOf("Disconnected", StringComparison.OrdinalIgnoreCase) >= 0
                || line.IndexOf("Connection ", StringComparison.OrdinalIgnoreCase) >= 0
                || line.IndexOf("fatal", StringComparison.OrdinalIgnoreCase) >= 0
                || line.IndexOf("error:", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        static AccessEvent Map(LogRead read, EventRecord record, FieldBag fields, string formatted, bool keepNoise)
        {
            switch (read.Kind)
            {
                case ChannelKind.Security:
                    return MapSecurity(read, record, fields, keepNoise);
                case ChannelKind.RemoteDesktop:
                    return MapRemoteDesktop(read, record, fields, formatted);
                case ChannelKind.RdpClient:
                    return MapRdpClient(read, record, fields, formatted);
                case ChannelKind.SshLog:
                    return MapSshRecord(read, record, fields, formatted);
                case ChannelKind.Gateway:
                    return MapGateway(read, record, fields, formatted);
                case ChannelKind.Smb:
                    return MapSmb(read, record, fields, formatted);
                default:
                    return null;
            }
        }

        static AccessEvent MapSecurity(LogRead read, EventRecord record, FieldBag fields, bool keepNoise)
        {
            int id = record.Id;
            if (id == 5140 || id == 5145)
                return MapShare(read, record, fields);

            string user = JoinUser(fields.Get("TargetDomainName", "Domain"), fields.Get("TargetUserName", "User"));
            string logonType = fields.Get("LogonType");
            string processName = Useful(fields.Get("ProcessName"));
            string logonProcess = Useful(fields.Get("LogonProcessName"));
            string package = Useful(fields.Get("AuthenticationPackageName"));
            string workstation = fields.Get("WorkstationName", "ClientName");
            string address = FormatAddress(fields.Get("IpAddress", "ClientAddress", "Address"), "");
            string port = CleanPort(fields.Get("IpPort", "ClientPort"));

            bool failure = id == 4625;
            if (!keepNoise && !failure && IsNoiseAccount(user))
                return null;

            var ev = NewEvent(read, record);
            ev.User = user;
            ev.Address = address;
            ev.Port = port;
            ev.LogonType = LogonTypeName(logonType);

            bool ssh = ContainsSsh(processName) || ContainsSsh(logonProcess);
            bool remoteLogon = logonType == "10" || logonType == "12";
            bool rdp = remoteLogon || id == 4778 || id == 4779;
            if (ssh) ev.Source = "SSH";
            else if (rdp) ev.Source = "RDP";
            else if (logonType == "3" || logonType == "8") ev.Source = "Network";
            else if (logonType == "2" || logonType == "7" || logonType == "11" || logonType == "13" || logonType == "9") ev.Source = "Console";
            else if (id == 4647) ev.Source = "Session";
            else ev.Source = "Other";

            if (ssh || remoteLogon || ev.Source == "Network" || IsRemoteAddress(address))
                ev.Direction = "In";
            else
                ev.Direction = "Local";

            if (failure) ev.Result = "Failure";
            else if (id == 4647) ev.Result = "Logoff";
            else if (id == 4779) ev.Result = "Disconnect";
            else if (id == 4778) ev.Result = "Reconnect";
            else ev.Result = "Success";

            if (id == 4778) ev.Action = "Remote Desktop reconnect";
            else if (id == 4779) ev.Action = "Remote Desktop disconnect";
            else if (id == 4647) ev.Action = "Sign out";
            else ev.Action = DescribeSecurityAction(ev.Source, logonType, logonProcess, package, processName);

            string lead = ev.Action;
            if (ev.Result == "Failure")
                lead = "Failed " + ev.Action;
            else if (ev.Result == "Logoff")
                lead = "Signed out";
            else if (ev.Result == "Disconnect")
                lead = ev.Action;
            else if (ev.Result == "Reconnect")
                lead = ev.Action;

            string why = failure ? ExplainFailure(fields.Get("Status"), fields.Get("SubStatus")) : "";
            string from = "";
            if (address.Length > 0 && !address.Equals("local", StringComparison.OrdinalIgnoreCase))
                from = "from " + address;
            else if (workstation.Length > 0 && workstation != "-" && !workstation.Equals("LOCAL", StringComparison.OrdinalIgnoreCase))
                from = "workstation " + workstation;
            if (ev.Port.Length > 0)
                from = (from.Length > 0 ? from + " " : "") + "port " + ev.Port;

            ev.Summary = JoinParts(lead, why, from);
            return ev;
        }

        static AccessEvent MapShare(LogRead read, EventRecord record, FieldBag fields)
        {
            string share = Useful(fields.Get("ShareName"));
            string relative = fields.Get("RelativeTargetName").Trim();
            string action;
            if (record.Id == 5145 && relative.Length > 0 && relative != "\\")
                action = "Open " + share + (relative.StartsWith("\\", StringComparison.Ordinal) ? relative : "\\" + relative);
            else if (share.Length > 0)
                action = "Open share " + share;
            else
                action = "Open a network share";

            var ev = NewEvent(read, record);
            ev.Source = "Network";
            ev.Direction = "In";
            ev.Result = "Success";
            ev.LogonType = "File share";
            ev.Action = action;
            ev.User = JoinUser(fields.Get("SubjectDomainName"), fields.Get("SubjectUserName", "SubjectUser"));
            ev.Address = FormatAddress(fields.Get("IpAddress"), "");
            ev.Port = CleanPort(fields.Get("IpPort"));
            ev.Summary = JoinParts(action, ev.Address.Length > 0 ? "from " + ev.Address : "", ev.Port.Length > 0 ? "port " + ev.Port : "");
            return ev;
        }

        static AccessEvent MapSmb(LogRead read, EventRecord record, FieldBag fields, string formatted)
        {
            string ip;
            string port;
            if (!TryDecodeSockaddr(fields.Get("ClientAddress"), out ip, out port))
            {
                string name = fields.Get("ClientName").Trim().TrimStart('\\');
                SplitEndpoint(name, out ip, out port);
            }
            if (ip.Length == 0)
                TryEndpoint(formatted, out ip, out port);

            string spn = fields.Get("SPN");
            string action = IsRealSpn(spn) ? "SMB sign-in to " + spn.Trim() : "SMB sign-in";
            var ev = NewEvent(read, record);
            ev.Source = "Network";
            ev.Direction = "In";
            ev.Result = "Failure";
            ev.LogonType = "SMB";
            ev.Action = action;
            ev.User = Useful(fields.Get("UserName"));
            ev.Address = FormatAddress(ip, "");
            ev.Port = CleanPort(port);
            string why = ExplainFailure(fields.Get("Status"), "");
            ev.Summary = JoinParts(
                "Failed " + action,
                why,
                ev.Address.Length > 0 ? "from " + ev.Address : "",
                ev.Port.Length > 0 ? "port " + ev.Port : "");
            ev.Message = BuildMessage(record, formatted, fields);
            return ev;
        }

        static AccessEvent MapRemoteDesktop(LogRead read, EventRecord record, FieldBag fields, string formatted)
        {
            int id = record.Id;
            string domain = fields.Get("Domain");
            string session = fields.Get("SessionID", "SessionId", "Session");
            string user = fields.Get("User", "Param1");
            string address;
            string port;
            ReadClientEndpoint(fields, formatted, out address, out port);

            if (id == 1149)
            {
                if (domain.Length == 0)
                    domain = fields.Get("Param2");
            }
            else if (session.Length == 0)
            {
                var param2 = fields.Get("Param2");
                int number;
                if (int.TryParse(param2, NumberStyles.Integer, CultureInfo.InvariantCulture, out number))
                    session = param2;
            }

            var ev = NewEvent(read, record);
            ev.Source = "RDP";
            ev.LogonType = "Remote Desktop";
            ev.User = JoinUser(domain, user);
            ev.Address = address;
            ev.Port = port;
            ev.Message = BuildMessage(record, formatted, fields);

            switch (id)
            {
                case 1149:
                    ev.Result = "Success";
                    ev.Summary = "Authentication succeeded";
                    break;
                case 261:
                    ev.Result = "Connect";
                    ev.Summary = "Incoming connection";
                    break;
                case 131:
                    ev.Result = "Connect";
                    string transport = fields.Get("ConnType");
                    ev.Summary = transport.Length > 0
                        ? "Incoming " + transport + " connection"
                        : "Incoming connection";
                    break;
                case 21:
                    ev.Result = "Success";
                    ev.Summary = "Session started";
                    break;
                case 22:
                    ev.Result = "Info";
                    ev.Summary = "Shell started";
                    break;
                case 23:
                    ev.Result = "Logoff";
                    ev.Summary = "Session signed out";
                    break;
                case 24:
                case 39:
                case 40:
                    ev.Result = "Disconnect";
                    ev.Summary = "Session disconnected";
                    break;
                case 25:
                    ev.Result = "Reconnect";
                    ev.Summary = "Session reconnected";
                    break;
                default:
                    ApplyLooseClass(ev, formatted);
                    if (string.IsNullOrEmpty(ev.Summary))
                        ev.Summary = "Remote Desktop event " + id.ToString(CultureInfo.InvariantCulture);
                    break;
            }

            ev.Action = ev.Summary;
            if (session.Length > 0 && id != 1149)
                ev.Summary = ev.Summary + " | session " + session;
            if (ev.Address.Length > 0
                && !ev.Address.Equals("local", StringComparison.OrdinalIgnoreCase)
                && ev.Summary.IndexOf(ev.Address, StringComparison.OrdinalIgnoreCase) < 0)
                ev.Summary = ev.Summary + " | from " + ev.Address;
            if (ev.Port.Length > 0 && ev.Summary.IndexOf("port " + ev.Port, StringComparison.OrdinalIgnoreCase) < 0)
                ev.Summary = ev.Summary + " | port " + ev.Port;
            ev.Direction = (id == 1149 || id == 261 || id == 131 || IsRemoteAddress(ev.Address)) ? "In" : "Local";
            return ev;
        }

        static AccessEvent MapRdpClient(LogRead read, EventRecord record, FieldBag fields, string formatted)
        {
            int id = record.Id;
            string target = ClientTarget(fields);
            var ev = NewEvent(read, record);
            ev.Source = "RDP";
            ev.Direction = "Out";
            ev.LogonType = "Outbound";
            ev.Address = FormatAddress(target, "");
            ev.Action = "Outbound Remote Desktop";
            ev.Message = BuildMessage(record, formatted, fields);

            switch (id)
            {
                case 1024:
                    ev.Result = "Connect";
                    ev.Summary = "Connecting";
                    break;
                case 1025:
                    ev.Result = "Success";
                    ev.Summary = "Connected";
                    break;
                case 1026:
                    ev.Result = "Disconnect";
                    ev.Summary = "Disconnected";
                    string reason = ClientValue(fields, "Disconnect Reason");
                    if (reason.Length > 0)
                        ev.Summary = ev.Summary + " | reason " + reason;
                    break;
                case 1027:
                    ev.Result = "Success";
                    ev.Summary = "Signed in";
                    string domain = fields.Get("DomainName");
                    string session = fields.Get("SessionId", "SessionID");
                    if (domain.Length > 0)
                        ev.Summary = ev.Summary + " | domain " + domain;
                    if (session.Length > 0)
                        ev.Summary = ev.Summary + " | session " + session;
                    break;
                default:
                    ev.Result = "Info";
                    ev.Summary = "Outbound Remote Desktop";
                    break;
            }

            if (ev.Address.Length > 0 && ev.Summary.IndexOf(ev.Address, StringComparison.OrdinalIgnoreCase) < 0)
                ev.Summary = ev.Summary + " | to " + ev.Address;
            return ev;
        }

        static AccessEvent MapSshRecord(LogRead read, EventRecord record, FieldBag fields, string formatted)
        {
            var when = ToLocal(record.TimeCreated);
            var text = string.IsNullOrWhiteSpace(formatted) ? FieldDump(fields) : formatted;
            var ev = FromSshText(text, when, read.LogName, read.Channel, record.Id, record.RecordId ?? 0);
            ev.Message = BuildMessage(record, formatted, fields);
            if (string.IsNullOrEmpty(ev.User))
                ev.User = JoinUser(fields.Get("TargetDomainName", "Domain"), fields.Get("TargetUserName", "User", "Param1"));
            if (string.IsNullOrEmpty(ev.Address))
                ev.Address = FormatAddress(fields.Get("IpAddress", "Address", "Param3"), fields.Get("IpPort"));
            return ev;
        }

        static AccessEvent MapGateway(LogRead read, EventRecord record, FieldBag fields, string formatted)
        {
            var ev = NewEvent(read, record);
            ev.Source = "RDP";
            ev.Direction = "In";
            ev.Action = "Remote Desktop gateway";
            ev.LogonType = "RD Gateway";
            ev.User = JoinUser(fields.Get("Domain"), fields.Get("User", "Param1"));
            ev.Address = FormatAddress(fields.Get("IpAddress", "Address", "Param2", "Param3"), "");
            ev.Message = BuildMessage(record, formatted, fields);
            ApplyLooseClass(ev, string.IsNullOrWhiteSpace(formatted) ? FieldDump(fields) : formatted);
            if (string.IsNullOrEmpty(ev.User))
                ev.User = TryUser(formatted);
            if (string.IsNullOrEmpty(ev.Address))
                ev.Address = TryIp(formatted);
            return ev;
        }

        static AccessEvent FromSshText(string message, DateTime localTime, string logName, string channel, int eventId, long recordId)
        {
            var ev = new AccessEvent
            {
                Time = localTime,
                LogName = logName,
                Channel = channel,
                EventId = eventId,
                RecordId = recordId,
                Source = "SSH",
                Direction = "In",
                Message = (message ?? "").Trim(),
                User = "",
                Address = "",
                Port = "",
                Action = "",
                LogonType = "",
                Result = "",
                Summary = ""
            };
            ApplyMessageClass(ev, message ?? "");
            if (string.IsNullOrEmpty(ev.Result))
                ApplyLooseClass(ev, message ?? "");
            return ev;
        }

        static void ApplyMessageClass(AccessEvent ev, string message)
        {
            var accepted = SshAccepted.Match(message);
            if (accepted.Success)
            {
                FillSsh(ev, accepted, "Success");
                ev.Action = "SSH sign-in";
                ev.Summary = "Accepted " + ev.LogonType;
                return;
            }

            var failed = SshFailed.Match(message);
            if (failed.Success)
            {
                FillSsh(ev, failed, "Failure");
                ev.Action = "SSH sign-in";
                bool invalid = message.IndexOf("invalid user", StringComparison.OrdinalIgnoreCase) >= 0;
                ev.Summary = invalid ? "Invalid user" : "Failed " + ev.LogonType;
                return;
            }

            var invalidUser = SshInvalid.Match(message);
            if (invalidUser.Success)
            {
                FillSsh(ev, invalidUser, "Failure");
                ev.Action = "SSH sign-in";
                ev.LogonType = "SSH";
                ev.Summary = "Invalid user";
                return;
            }

            var connect = SshConnect.Match(message);
            if (connect.Success)
            {
                FillSsh(ev, connect, "Connect");
                ev.Action = "SSH connection";
                ev.LogonType = "SSH";
                ev.Summary = "Connection opened";
                return;
            }

            var closed = SshClosed.Match(message);
            if (!closed.Success)
                closed = SshConnectionClosed.Match(message);
            if (closed.Success)
            {
                FillSsh(ev, closed, "Disconnect");
                ev.Action = "SSH disconnect";
                ev.LogonType = "SSH";
                ev.Summary = "Disconnected";
            }
        }

        static void FillSsh(AccessEvent ev, Match match, string result)
        {
            ev.Result = result;
            var user = match.Groups["user"];
            if (user.Success)
                ev.User = user.Value.Trim();
            var method = match.Groups["method"];
            if (method.Success && method.Value.Length > 0)
                ev.LogonType = method.Value;
            var ip = match.Groups["ip"];
            var port = match.Groups["port"];
            if (ip.Success)
            {
                ev.Address = FormatAddress(ip.Value, "");
                ev.Port = CleanPort(port.Success ? port.Value : "");
            }
        }

        static void ApplyLooseClass(AccessEvent ev, string message)
        {
            var text = message ?? "";
            if (text.IndexOf("fail", StringComparison.OrdinalIgnoreCase) >= 0
                || text.IndexOf("denied", StringComparison.OrdinalIgnoreCase) >= 0
                || text.IndexOf("invalid", StringComparison.OrdinalIgnoreCase) >= 0
                || text.IndexOf("error", StringComparison.OrdinalIgnoreCase) >= 0)
                ev.Result = "Failure";
            else if (text.IndexOf("disconnect", StringComparison.OrdinalIgnoreCase) >= 0
                || text.IndexOf("logged off", StringComparison.OrdinalIgnoreCase) >= 0
                || text.IndexOf("logoff", StringComparison.OrdinalIgnoreCase) >= 0
                || text.IndexOf("signed out", StringComparison.OrdinalIgnoreCase) >= 0)
                ev.Result = "Disconnect";
            else if (text.IndexOf("reconnect", StringComparison.OrdinalIgnoreCase) >= 0)
                ev.Result = "Reconnect";
            else if (text.IndexOf("accept", StringComparison.OrdinalIgnoreCase) >= 0
                || text.IndexOf("success", StringComparison.OrdinalIgnoreCase) >= 0
                || text.IndexOf("connected", StringComparison.OrdinalIgnoreCase) >= 0
                || text.IndexOf("logon", StringComparison.OrdinalIgnoreCase) >= 0
                || text.IndexOf("log on", StringComparison.OrdinalIgnoreCase) >= 0)
                ev.Result = "Success";
            else
                ev.Result = string.IsNullOrEmpty(ev.Result) ? "Info" : ev.Result;

            ev.Summary = OneLine(text, 180);
            if (string.IsNullOrEmpty(ev.Summary))
                ev.Summary = ev.Result;
        }

        static AccessEvent NewEvent(LogRead read, EventRecord record)
        {
            return new AccessEvent
            {
                Time = ToLocal(record.TimeCreated),
                Channel = read.Channel,
                LogName = read.LogName,
                EventId = record.Id,
                RecordId = record.RecordId ?? 0,
                User = "",
                Address = "",
                LogonType = "",
                Source = "",
                Direction = "",
                Port = "",
                Action = "",
                Result = "",
                Summary = "",
                Message = ""
            };
        }

        static string BuildMessage(EventRecord record, string formatted, FieldBag fields)
        {
            var sb = new StringBuilder();
            sb.Append("Event ").Append(record.Id);
            sb.Append("  |  ").Append(record.LogName ?? "");
            if (record.RecordId.HasValue)
                sb.Append("  |  record ").Append(record.RecordId.Value.ToString(CultureInfo.InvariantCulture));
            sb.AppendLine();
            if (record.TimeCreated.HasValue)
                sb.Append("Time: ").Append(ToLocal(record.TimeCreated).ToString("yyyy-MM-dd HH:mm:ss")).AppendLine();
            if (!string.IsNullOrEmpty(record.MachineName))
                sb.Append("Computer: ").Append(record.MachineName).AppendLine();
            if (!string.IsNullOrEmpty(record.ProviderName))
                sb.Append("Source: ").Append(record.ProviderName).AppendLine();
            sb.AppendLine();
            if (!string.IsNullOrWhiteSpace(formatted))
            {
                sb.AppendLine(formatted.Trim());
                sb.AppendLine();
            }
            if (fields != null && fields.Items.Count > 0)
            {
                sb.AppendLine("Fields:");
                foreach (var pair in fields.Items)
                {
                    if (string.IsNullOrWhiteSpace(pair.Value))
                        continue;
                    var value = pair.Value.Trim();
                    if (value.Length > 2000)
                        value = value.Substring(0, 2000) + "...";
                    sb.Append("  ").Append(pair.Key).Append(" = ").AppendLine(value);
                }
            }
            return sb.ToString().TrimEnd();
        }

        static FieldBag ReadFields(EventRecord record)
        {
            var bag = new FieldBag();
            string xml;
            try
            {
                xml = record.ToXml();
            }
            catch (EventLogException)
            {
                return bag;
            }

            XDocument doc;
            try
            {
                doc = XDocument.Parse(xml);
            }
            catch (XmlException)
            {
                return bag;
            }

            int dataIndex = 0;
            foreach (var el in doc.Descendants())
            {
                if (el.Name.LocalName == "Data")
                {
                    var nameAttr = el.Attribute("Name");
                    var name = nameAttr == null || string.IsNullOrEmpty(nameAttr.Value)
                        ? "Data" + dataIndex.ToString(CultureInfo.InvariantCulture)
                        : nameAttr.Value;
                    dataIndex++;
                    bag.Add(name, el.Value);
                }
                else if (!el.HasElements && IsUnder(el, "UserData"))
                {
                    bag.Add(el.Name.LocalName, el.Value);
                }
            }
            return bag;
        }

        static string FieldDump(FieldBag fields)
        {
            if (fields == null || fields.Items.Count == 0)
                return "";
            var sb = new StringBuilder();
            foreach (var pair in fields.Items)
            {
                if (string.IsNullOrWhiteSpace(pair.Value))
                    continue;
                if (sb.Length > 0)
                    sb.Append(' ');
                sb.Append(pair.Key).Append('=').Append(pair.Value.Trim());
            }
            return sb.ToString();
        }

        static string FormatMessage(EventRecord record)
        {
            try
            {
                return record.FormatDescription() ?? "";
            }
            catch (EventLogException)
            {
                return "";
            }
        }

        static string DedupeKey(AccessEvent ev)
        {
            if (ev.RecordId > 0)
                return (ev.LogName ?? "") + "|" + ev.RecordId.ToString(CultureInfo.InvariantCulture);
            return (ev.LogName ?? "") + "|t" + ev.Time.Ticks.ToString(CultureInfo.InvariantCulture)
                + "|" + (ev.User ?? "") + "|" + (ev.Summary ?? "");
        }

        static string TimeClause(DateTime sinceUtc)
        {
            var stamp = sinceUtc.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fff'Z'", CultureInfo.InvariantCulture);
            return "TimeCreated[@SystemTime>='" + stamp + "']";
        }

        static string TimeOnly(string timeClause)
        {
            return "*[System[" + timeClause + "]]";
        }

        static string SystemIds(string timeClause, params int[] ids)
        {
            return "*[System[(" + IdList(ids) + ") and " + timeClause + "]]";
        }

        static string WithTypes(string timeClause, int[] ids, params int[] types)
        {
            return "*[System[(" + IdList(ids) + ") and " + timeClause + "] and EventData[" + TypeList(types) + "]]";
        }

        static string WithSshProcess(string timeClause, params int[] ids)
        {
            return "*[System[(" + IdList(ids) + ") and " + timeClause + "] and EventData["
                + "(Data[@Name='ProcessName' and (contains(., 'sshd') or contains(., 'SSHD') or contains(., 'OpenSSH'))])"
                + " or (Data[@Name='LogonProcessName' and (contains(., 'sshd') or contains(., 'SSHD'))])"
                + "]]";
        }

        static string IdList(int[] ids)
        {
            var parts = new string[ids.Length];
            for (int i = 0; i < ids.Length; i++)
                parts[i] = "EventID=" + ids[i].ToString(CultureInfo.InvariantCulture);
            return string.Join(" or ", parts);
        }

        static string TypeList(int[] types)
        {
            var parts = new string[types.Length];
            for (int i = 0; i < types.Length; i++)
                parts[i] = "(Data[@Name='LogonType']='" + types[i].ToString(CultureInfo.InvariantCulture) + "')";
            return string.Join(" or ", parts);
        }

        static string LogonTypeName(string code)
        {
            switch (code)
            {
                case "2": return "Interactive";
                case "3": return "Network";
                case "4": return "Batch";
                case "5": return "Service";
                case "7": return "Unlock";
                case "8": return "Network cleartext";
                case "9": return "New credentials";
                case "10": return "Remote Desktop";
                case "11": return "Cached interactive";
                case "12": return "Cached Remote Desktop";
                case "13": return "Cached unlock";
                default:
                    return string.IsNullOrEmpty(code) ? "" : "Type " + code;
            }
        }

        static string ExplainFailure(string status, string subStatus)
        {
            uint sub = ParseCode(subStatus);
            uint st = ParseCode(status);
            uint code = sub != 0 ? sub : st;
            if (code == 0)
                return "";

            string meaning;
            switch (code)
            {
                case 0xC0000064: meaning = "Unknown user name"; break;
                case 0xC000006A: meaning = "Wrong password"; break;
                case 0xC000006D: meaning = "Logon failure"; break;
                case 0xC000006E: meaning = "Account restriction"; break;
                case 0xC000006F: meaning = "Outside allowed hours"; break;
                case 0xC0000070: meaning = "Unauthorized workstation"; break;
                case 0xC0000071: meaning = "Password expired"; break;
                case 0xC0000072: meaning = "Account disabled"; break;
                case 0xC0000133: meaning = "Clock out of sync"; break;
                case 0xC000015B: meaning = "Logon type not permitted"; break;
                case 0xC000018D: meaning = "Trust relationship failed"; break;
                case 0xC0000193: meaning = "Account expired"; break;
                case 0xC0000224: meaning = "Password must be changed"; break;
                case 0xC0000234: meaning = "Account locked out"; break;
                default: meaning = "Status"; break;
            }
            return meaning + " (0x" + code.ToString("X8") + ")";
        }

        static uint ParseCode(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return 0;
            text = text.Trim();
            if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                text = text.Substring(2);
            uint value;
            if (uint.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value))
                return value;
            return 0;
        }

        static bool IsNoiseAccount(string user)
        {
            if (string.IsNullOrWhiteSpace(user))
                return true;
            int slash = user.LastIndexOf('\\');
            var name = slash >= 0 ? user.Substring(slash + 1) : user;
            name = name.Trim();
            if (name.Length == 0 || name == "-")
                return true;
            if (name[name.Length - 1] == '$')
                return true;
            if (name.StartsWith("DWM-", StringComparison.OrdinalIgnoreCase))
                return true;
            if (name.StartsWith("UMFD-", StringComparison.OrdinalIgnoreCase))
                return true;
            return name.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase)
                || name.Equals("LOCAL SERVICE", StringComparison.OrdinalIgnoreCase)
                || name.Equals("NETWORK SERVICE", StringComparison.OrdinalIgnoreCase)
                || name.Equals("ANONYMOUS LOGON", StringComparison.OrdinalIgnoreCase)
                || name.Equals("IUSR", StringComparison.OrdinalIgnoreCase);
        }

        static bool ContainsSsh(string process)
        {
            if (string.IsNullOrEmpty(process))
                return false;
            return process.IndexOf("sshd", StringComparison.OrdinalIgnoreCase) >= 0
                || process.IndexOf("OpenSSH", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        static string JoinUser(string domain, string user)
        {
            user = (user ?? "").Trim();
            domain = (domain ?? "").Trim();
            if (user.Length == 0 || user == "-")
                return "";
            if (user.IndexOf('\\') >= 0)
                return user;
            if (domain.Length == 0 || domain == "-")
                return user;
            return domain + "\\" + user;
        }

        static void DropUnaddressedListenerEvents(AccessLogResult result)
        {
            var addressed = new List<DateTime>();
            foreach (var ev in result.Events)
            {
                if (ev.EventId == 131 && IsRemoteAddress(ev.Address))
                    addressed.Add(ev.Time);
            }
            if (addressed.Count == 0)
                return;

            result.Events.RemoveAll(ev =>
            {
                if (ev.EventId != 261 || IsRemoteAddress(ev.Address))
                    return false;
                foreach (var time in addressed)
                {
                    double seconds = ev.Time.Subtract(time).TotalSeconds;
                    if (seconds < 0)
                        seconds = -seconds;
                    if (seconds <= 3)
                        return true;
                }
                return false;
            });
        }

        static void ReadClientEndpoint(FieldBag fields, string formatted, out string address, out string port)
        {
            string raw = fields.Get(
                "Address",
                "SourceNetworkAddress",
                "Param3",
                "ClientIP",
                "IpAddress",
                "IPAddress",
                "IPString",
                "ClientAddress");
            string ip;
            string parsedPort;
            SplitEndpoint(raw, out ip, out parsedPort);
            port = CleanPort(parsedPort);
            if (port.Length == 0)
                port = CleanPort(fields.Get("IpPort", "ClientPort", "Port"));
            if (ip.Length == 0)
            {
                string foundIp;
                string foundPort;
                if (TryEndpoint(formatted, out foundIp, out foundPort) || TryEndpoint(FieldDump(fields), out foundIp, out foundPort))
                {
                    ip = foundIp;
                    if (port.Length == 0)
                        port = CleanPort(foundPort);
                }
            }
            address = FormatAddress(ip, "");
        }

        static void MergeSmbAttempts(AccessLogResult result)
        {
            var smb = new List<AccessEvent>();
            var logons = new List<AccessEvent>();
            foreach (var ev in result.Events)
            {
                if (ev.EventId == 551)
                    smb.Add(ev);
                else if (ev.EventId == 4624 || ev.EventId == 4625)
                    logons.Add(ev);
            }
            if (smb.Count == 0)
                return;

            var consumed = new HashSet<AccessEvent>();
            var used = new HashSet<AccessEvent>();
            foreach (var share in smb)
            {
                AccessEvent best = null;
                double bestDelta = 5;
                foreach (var logon in logons)
                {
                    if (used.Contains(logon))
                        continue;
                    if (!SameHost(share.Address, logon.Address))
                        continue;
                    if (!UsersCompatible(share.User, logon.User))
                        continue;
                    double seconds = share.Time.Subtract(logon.Time).TotalSeconds;
                    if (seconds < 0)
                        seconds = -seconds;
                    if (seconds < bestDelta)
                    {
                        bestDelta = seconds;
                        best = logon;
                    }
                }
                if (best == null)
                    continue;

                used.Add(best);
                consumed.Add(share);
                if (best.Port.Length == 0 && share.Port.Length > 0)
                {
                    best.Port = share.Port;
                    if (best.Summary.IndexOf("port " + share.Port, StringComparison.OrdinalIgnoreCase) < 0)
                        best.Summary = JoinParts(best.Summary, "port " + share.Port);
                }
                if (share.Action.IndexOf(" to ", StringComparison.OrdinalIgnoreCase) >= 0)
                    best.Action = share.Action;
                else if (best.Action.IndexOf("network sign-in", StringComparison.OrdinalIgnoreCase) >= 0)
                    best.Action = best.Action.Replace("network sign-in", "SMB sign-in");
                else if (best.Action.IndexOf("SMB", StringComparison.OrdinalIgnoreCase) < 0)
                    best.Action = share.Action;

                best.Summary = best.Summary
                    .Replace("NTLM network sign-in", "NTLM SMB sign-in")
                    .Replace("Kerberos network sign-in", "Kerberos SMB sign-in")
                    .Replace("Negotiate network sign-in", "Negotiate SMB sign-in")
                    .Replace("Cleartext network sign-in", "Cleartext SMB sign-in");
                if (best.Summary.IndexOf("SMB", StringComparison.OrdinalIgnoreCase) < 0)
                    best.Summary = "SMB | " + best.Summary;
            }

            if (consumed.Count > 0)
                result.Events.RemoveAll(ev => consumed.Contains(ev));
        }

        static bool SameHost(string left, string right)
        {
            left = HostOf(left);
            right = HostOf(right);
            return left.Length > 0
                && !left.Equals("local", StringComparison.OrdinalIgnoreCase)
                && left.Equals(right, StringComparison.OrdinalIgnoreCase);
        }

        static string HostOf(string address)
        {
            if (string.IsNullOrWhiteSpace(address))
                return "";
            address = address.Trim();
            if (address.StartsWith("[", StringComparison.Ordinal))
            {
                int end = address.IndexOf(']');
                if (end > 1)
                    return address.Substring(1, end - 1);
            }
            int colon = address.IndexOf(':');
            if (colon > 0 && colon == address.LastIndexOf(':'))
                return address.Substring(0, colon);
            return address;
        }

        static bool UsersCompatible(string left, string right)
        {
            left = AccountName(left);
            right = AccountName(right);
            if (left.Length == 0 || right.Length == 0)
                return true;
            return left.Equals(right, StringComparison.OrdinalIgnoreCase);
        }

        static string AccountName(string user)
        {
            user = Useful(user);
            int slash = user.LastIndexOf('\\');
            if (slash >= 0 && slash < user.Length - 1)
                user = user.Substring(slash + 1);
            return user;
        }

        static string DescribeSecurityAction(string source, string logonType, string logonProcess, string package, string processName)
        {
            string service = ServiceFromProcess(processName);
            if (service.Length > 0)
                return service;
            if (source == "RDP")
                return "Remote Desktop sign-in";
            if (source == "SSH")
                return "SSH sign-in";
            if (source == "Console")
                return logonType == "9" ? "Run as another user" : "Console sign-in";
            if (logonType == "4" || logonType == "5")
                return "Service sign-in";

            string method = AuthMethod(logonProcess, package);
            if (source == "Network" || logonType == "3" || logonType == "8")
            {
                if (logonType == "8")
                    return method.Length > 0 ? method + " cleartext network sign-in" : "Cleartext network sign-in";
                return method.Length > 0 ? method + " network sign-in" : "Network sign-in";
            }
            if (method.Length > 0)
                return method + " sign-in";
            return "Sign-in";
        }

        static string AuthMethod(string logonProcess, string package)
        {
            string blob = (logonProcess ?? "") + " " + (package ?? "");
            if (blob.IndexOf("NTLM", StringComparison.OrdinalIgnoreCase) >= 0
                || blob.IndexOf("NtLm", StringComparison.OrdinalIgnoreCase) >= 0)
                return "NTLM";
            if (blob.IndexOf("Kerberos", StringComparison.OrdinalIgnoreCase) >= 0)
                return "Kerberos";
            if (blob.IndexOf("Negotiate", StringComparison.OrdinalIgnoreCase) >= 0)
                return "Negotiate";
            return "";
        }

        static string ServiceFromProcess(string processName)
        {
            if (string.IsNullOrWhiteSpace(processName))
                return "";
            string file = Path.GetFileName(processName.Trim());
            if (file.Length == 0 || file == "-" || IsGenericProcess(file))
                return "";
            if (file.Equals("sqlservr.exe", StringComparison.OrdinalIgnoreCase))
                return "SQL Server sign-in";
            if (file.Equals("w3wp.exe", StringComparison.OrdinalIgnoreCase) || file.Equals("iisexpress.exe", StringComparison.OrdinalIgnoreCase))
                return "IIS sign-in";
            if (file.Equals("mysqld.exe", StringComparison.OrdinalIgnoreCase) || file.Equals("mysqld-nt.exe", StringComparison.OrdinalIgnoreCase))
                return "MySQL sign-in";
            if (file.Equals("postgres.exe", StringComparison.OrdinalIgnoreCase))
                return "PostgreSQL sign-in";
            if (file.IndexOf("tomcat", StringComparison.OrdinalIgnoreCase) >= 0)
                return "Tomcat sign-in";
            if (file.Equals("java.exe", StringComparison.OrdinalIgnoreCase) || file.Equals("javaw.exe", StringComparison.OrdinalIgnoreCase))
                return "Java sign-in";
            if (file.IndexOf("sshd", StringComparison.OrdinalIgnoreCase) >= 0 || file.IndexOf("OpenSSH", StringComparison.OrdinalIgnoreCase) >= 0)
                return "SSH sign-in";
            return "Sign-in via " + file;
        }

        static bool IsGenericProcess(string file)
        {
            return file.Equals("lsass.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("winlogon.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("services.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("csrss.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("dwm.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("sihost.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("userinit.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("logonui.exe", StringComparison.OrdinalIgnoreCase);
        }

        static string Useful(string value)
        {
            value = (value ?? "").Trim();
            if (value.Length == 0 || value == "-")
                return "";
            return value;
        }

        static bool IsRealSpn(string spn)
        {
            if (string.IsNullOrWhiteSpace(spn))
                return false;
            if (spn.IndexOf("failed", StringComparison.OrdinalIgnoreCase) >= 0)
                return false;
            return spn.IndexOf('/') >= 0;
        }

        static bool TryDecodeSockaddr(string raw, out string ip, out string port)
        {
            ip = "";
            port = "";
            if (string.IsNullOrWhiteSpace(raw))
                return false;
            raw = raw.Trim();
            if (raw.IndexOf('.') >= 0)
            {
                SplitEndpoint(raw, out ip, out port);
                return ip.Length > 0;
            }

            var hex = new StringBuilder();
            foreach (char ch in raw)
            {
                if ((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))
                    hex.Append(ch);
            }
            if (hex.Length < 16 || hex.Length % 2 != 0)
                return false;

            int length = hex.Length / 2;
            var data = new byte[length];
            for (int i = 0; i < length; i++)
                data[i] = byte.Parse(hex.ToString(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            if (data.Length < 8)
                return false;

            int family = data[0] | (data[1] << 8);
            int portNumber = (data[2] << 8) | data[3];
            if (portNumber > 0 && portNumber <= 65535)
                port = portNumber.ToString(CultureInfo.InvariantCulture);

            if (family == 2 && data.Length >= 8)
            {
                ip = data[4].ToString(CultureInfo.InvariantCulture) + "."
                    + data[5].ToString(CultureInfo.InvariantCulture) + "."
                    + data[6].ToString(CultureInfo.InvariantCulture) + "."
                    + data[7].ToString(CultureInfo.InvariantCulture);
                return true;
            }

            if (family == 23 && data.Length >= 24)
            {
                var addr = new byte[16];
                Buffer.BlockCopy(data, 8, addr, 0, 16);
                ip = new IPAddress(addr).ToString();
                return ip.Length > 0;
            }
            return false;
        }

        static bool TryEndpoint(string text, out string ip, out string port)
        {
            ip = "";
            port = "";
            if (string.IsNullOrEmpty(text))
                return false;
            Match withPort = null;
            foreach (Match match in EndpointInText.Matches(text))
            {
                if (match.Groups["port"].Success)
                {
                    withPort = match;
                    break;
                }
                if (ip.Length == 0)
                {
                    ip = match.Groups["ip"].Value;
                }
            }
            if (withPort != null)
            {
                ip = withPort.Groups["ip"].Value;
                port = withPort.Groups["port"].Value;
                return true;
            }
            return ip.Length > 0;
        }

        static string CleanPort(string port)
        {
            port = (port ?? "").Trim();
            int number;
            if (!int.TryParse(port, NumberStyles.Integer, CultureInfo.InvariantCulture, out number))
                return "";
            if (number <= 0 || number > 65535)
                return "";
            return number.ToString(CultureInfo.InvariantCulture);
        }

        static void SplitEndpoint(string raw, out string ip, out string port)
        {
            ip = "";
            port = "";
            raw = (raw ?? "").Trim();
            if (raw.Length == 0 || raw == "-")
                return;

            if (raw[0] == '[')
            {
                int end = raw.IndexOf(']');
                if (end > 1)
                {
                    ip = raw.Substring(1, end - 1);
                    if (end + 2 < raw.Length && raw[end + 1] == ':')
                        port = raw.Substring(end + 2);
                    return;
                }
            }

            int colon = raw.IndexOf(':');
            if (colon > 0 && colon == raw.LastIndexOf(':'))
            {
                string tail = raw.Substring(colon + 1);
                int portNumber;
                if (int.TryParse(tail, NumberStyles.Integer, CultureInfo.InvariantCulture, out portNumber))
                {
                    ip = raw.Substring(0, colon);
                    port = tail;
                    return;
                }
            }

            ip = raw;
        }

        static bool IsRemoteAddress(string address)
        {
            return !string.IsNullOrEmpty(address)
                && !address.Equals("local", StringComparison.OrdinalIgnoreCase);
        }

        static string ClientTarget(FieldBag fields)
        {
            string named = ClientValue(fields, "Server Name", "ServerAddress", "Server");
            if (named.Length > 0)
                return named;
            return fields.Get("ServerName", "ServerAddress");
        }

        static string ClientValue(FieldBag fields, params string[] names)
        {
            string label = fields.Get("Name");
            if (label.Length == 0)
                return "";
            foreach (var name in names)
            {
                if (label.Equals(name, StringComparison.OrdinalIgnoreCase))
                    return fields.Get("Value");
            }
            return "";
        }

        static string FormatAddress(string ip, string port)
        {
            ip = CleanIp(ip);
            if (ip.Length == 0)
                return "";
            port = (port ?? "").Trim();
            if (port.Length == 0 || port == "-" || port == "0")
                return ip;
            if (ip.IndexOf(':') >= 0)
                return "[" + ip + "]:" + port;
            return ip + ":" + port;
        }

        static string CleanIp(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip))
                return "";
            ip = ip.Trim();
            if (ip == "-" || ip == "::" || ip == "0.0.0.0")
                return "";
            if (ip == "::1" || ip == "127.0.0.1" || ip.Equals("LOCAL", StringComparison.OrdinalIgnoreCase))
                return "local";
            return ip;
        }

        static string TryUser(string message)
        {
            if (string.IsNullOrEmpty(message))
                return "";
            var match = Regex.Match(
                message,
                @"\b(?:User(?:name)?|Account)\s*[:=]\s*(?<user>[^\s,;]+)",
                RegexOptions.IgnoreCase);
            return match.Success ? match.Groups["user"].Value.Trim() : "";
        }

        static string TryIp(string message)
        {
            if (string.IsNullOrEmpty(message))
                return "";
            var match = Regex.Match(
                message,
                @"\b(?<ip>\d{1,3}(?:\.\d{1,3}){3})\b");
            return match.Success ? match.Groups["ip"].Value : "";
        }

        static string JoinParts(params string[] parts)
        {
            var list = new List<string>();
            foreach (var part in parts)
            {
                if (!string.IsNullOrWhiteSpace(part))
                    list.Add(part.Trim());
            }
            return string.Join(" | ", list.ToArray());
        }

        static string OneLine(string text, int max)
        {
            if (string.IsNullOrEmpty(text))
                return "";
            var sb = new StringBuilder(Math.Min(text.Length, max + 3));
            bool pendingSpace = false;
            foreach (var ch in text)
            {
                if (ch == '\r' || ch == '\n' || ch == '\t')
                {
                    pendingSpace = sb.Length > 0;
                    continue;
                }
                if (pendingSpace)
                {
                    sb.Append(' ');
                    pendingSpace = false;
                }
                sb.Append(ch);
                if (sb.Length >= max)
                {
                    sb.Append("...");
                    break;
                }
            }
            return sb.ToString();
        }

        static DateTime ToLocal(DateTime? value)
        {
            if (!value.HasValue)
                return DateTime.MinValue;
            var time = value.Value;
            if (time.Kind == DateTimeKind.Utc)
                return time.ToLocalTime();
            return time;
        }

        static DateTime? TryParseTimestamp(string line)
        {
            var iso = IsoTime.Match(line);
            if (iso.Success)
            {
                DateTime parsed;
                var styles = DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal;
                if (DateTime.TryParse(iso.Groups["ts"].Value, CultureInfo.InvariantCulture, styles, out parsed))
                    return parsed;
            }

            var sys = SyslogTime.Match(line);
            if (!sys.Success)
                return null;
            int month = Array.IndexOf(Months, sys.Groups["mon"].Value);
            if (month < 0)
                return null;
            int day;
            if (!int.TryParse(sys.Groups["day"].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out day))
                return null;
            TimeSpan time;
            if (!TimeSpan.TryParseExact(sys.Groups["time"].Value, @"hh\:mm\:ss", CultureInfo.InvariantCulture, out time))
                return null;
            try
            {
                int year = DateTime.Now.Year;
                var local = new DateTime(year, month + 1, day, time.Hours, time.Minutes, time.Seconds, DateTimeKind.Local);
                if (local > DateTime.Now.AddDays(2))
                    local = local.AddYears(-1);
                return local.ToUniversalTime();
            }
            catch (ArgumentException)
            {
                return null;
            }
        }

        static bool IsLocalComputer(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return true;
            if (name == "." || name.Equals("localhost", StringComparison.OrdinalIgnoreCase))
                return true;
            if (name == "127.0.0.1" || name == "::1")
                return true;
            if (name.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase))
                return true;
            if (name.StartsWith(Environment.MachineName + ".", StringComparison.OrdinalIgnoreCase))
                return true;
            try
            {
                if (name.Equals(Dns.GetHostName(), StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            catch (Exception)
            {
            }
            return false;
        }

        static bool IsUnder(XElement el, string localName)
        {
            for (var parent = el.Parent; parent != null; parent = parent.Parent)
            {
                if (parent.Name.LocalName == localName)
                    return true;
            }
            return false;
        }

        static string DescribeFailure(LogRead read, string error)
        {
            if (read.LogName == "Security" && IsAccessDenied(error))
                return "The Security log needs administrator rights. Sign-in auditing stays hidden until you restart this program as administrator.";
            if (string.IsNullOrEmpty(error))
                return read.Display + " could not be read.";
            if (IsAccessDenied(error))
                return read.Display + " needs administrator rights.";
            return read.Display + ": " + error;
        }

        static bool IsAccessDenied(string message)
        {
            if (string.IsNullOrEmpty(message))
                return false;
            return message.IndexOf("unauthorized", StringComparison.OrdinalIgnoreCase) >= 0
                || message.IndexOf("access is denied", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        static bool IsConnectionFailure(string message)
        {
            if (string.IsNullOrEmpty(message))
                return false;
            return message.IndexOf("RPC server", StringComparison.OrdinalIgnoreCase) >= 0
                || message.IndexOf("network path", StringComparison.OrdinalIgnoreCase) >= 0
                || message.IndexOf("unreachable", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        static void AddNote(AccessLogResult result, HashSet<string> noteSet, string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return;
            if (noteSet.Add(text))
                result.Notes.Add(text);
        }

        enum ChannelKind
        {
            Security,
            RemoteDesktop,
            RdpClient,
            SshLog,
            Gateway,
            Smb
        }

        enum ChannelOpen
        {
            Read,
            Missing,
            Failed
        }

        sealed class LogRead
        {
            public LogRead(string logName, string display, string channel, string xpath, ChannelKind kind, bool optional, bool warningsOnly)
            {
                LogName = logName;
                Display = display;
                Channel = channel;
                XPath = xpath;
                Kind = kind;
                Optional = optional;
                WarningsOnly = warningsOnly;
            }

            public string LogName { get; private set; }
            public string Display { get; private set; }
            public string Channel { get; private set; }
            public string XPath { get; private set; }
            public ChannelKind Kind { get; private set; }
            public bool Optional { get; private set; }
            public bool WarningsOnly { get; private set; }
        }

        sealed class FieldBag
        {
            readonly Dictionary<string, string> map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            public readonly List<KeyValuePair<string, string>> Items = new List<KeyValuePair<string, string>>();

            public void Add(string name, string value)
            {
                if (string.IsNullOrEmpty(name) || map.ContainsKey(name))
                    return;
                map[name] = value ?? "";
                Items.Add(new KeyValuePair<string, string>(name, value ?? ""));
            }

            public string Get(params string[] names)
            {
                foreach (var name in names)
                {
                    string value;
                    if (map.TryGetValue(name, out value) && !string.IsNullOrWhiteSpace(value))
                        return value.Trim();
                }
                return "";
            }
        }
    }
}
