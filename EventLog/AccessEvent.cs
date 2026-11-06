using System;

namespace EventLog
{
    public sealed class AccessEvent
    {
        public DateTime Time { get; set; }
        public string Source { get; set; }
        public string Direction { get; set; }
        public string Result { get; set; }
        public string User { get; set; }
        public string Address { get; set; }
        public string LogonType { get; set; }
        public int EventId { get; set; }
        public long RecordId { get; set; }
        public string Channel { get; set; }
        public string LogName { get; set; }
        public string Summary { get; set; }
        public string Message { get; set; }
    }

    public sealed class AccessQuery
    {
        public AccessQuery()
        {
            Hours = 24 * 7;
            MaxEvents = 2000;
            Rdp = true;
            Ssh = true;
            Console = true;
            Failures = true;
            SignOut = true;
        }

        public int Hours { get; set; }
        public int MaxEvents { get; set; }
        public string Computer { get; set; }
        public bool Rdp { get; set; }
        public bool Ssh { get; set; }
        public bool Console { get; set; }
        public bool Network { get; set; }
        public bool Failures { get; set; }
        public bool SignOut { get; set; }
        public bool ServiceAccounts { get; set; }
    }

    public sealed class AccessLogResult
    {
        public AccessLogResult()
        {
            Events = new System.Collections.Generic.List<AccessEvent>();
            Notes = new System.Collections.Generic.List<string>();
        }

        public System.Collections.Generic.List<AccessEvent> Events { get; private set; }
        public System.Collections.Generic.List<string> Notes { get; private set; }
        public string Computer { get; set; }
        public bool Truncated { get; set; }
    }
}
