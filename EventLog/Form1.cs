using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace EventLog
{
    public partial class Form1 : Form
    {
        static readonly Color Navy = Color.FromArgb(23, 43, 58);
        static readonly Color Teal = Color.FromArgb(14, 122, 118);
        static readonly Color Ink = Color.FromArgb(32, 41, 49);
        static readonly Color Muted = Color.FromArgb(90, 104, 116);
        static readonly Color Page = Color.FromArgb(241, 244, 247);
        static readonly Color Line = Color.FromArgb(220, 226, 232);
        static readonly Color FailBg = Color.FromArgb(253, 236, 234);
        static readonly Color FailFg = Color.FromArgb(153, 40, 32);
        static readonly Color ConnectBg = Color.FromArgb(255, 248, 230);

        readonly Font boldFont;
        readonly Font titleFont;
        readonly Font detailFont;
        readonly ToolTip tips;

        Label machineLabel;
        Label subtitleLabel;
        Panel banner;
        ComboBox rangeBox;
        TextBox computerBox;
        NumericUpDown maxBox;
        Button refreshButton;
        Button exportButton;
        CheckBox rdpBox;
        CheckBox sshBox;
        CheckBox consoleBox;
        CheckBox networkBox;
        CheckBox failureBox;
        CheckBox signOutBox;
        CheckBox serviceBox;
        Label rdpCount;
        Label sshCount;
        Label failureCount;
        Label addressCount;
        Label succeededCaption;
        Label failedCaption;
        ListView succeededList;
        ListView failedList;
        bool fillingAddresses;
        TextBox filterBox;
        ComboBox directionBox;
        Label showingLabel;
        DataGridView grid;
        TextBox detailBox;
        ToolStripStatusLabel statusLabel;
        ToolStripStatusLabel elevationLabel;

        DataTable table;
        DataView view;
        CancellationTokenSource loadCancel;
        int generation;
        bool busy;
        bool started;

        public Form1()
        {
            InitializeComponent();
            boldFont = CreateFont("Segoe UI", 9F, FontStyle.Bold);
            titleFont = CreateFont("Segoe UI", 16F, FontStyle.Bold);
            detailFont = CreateFont("Consolas", 10F, FontStyle.Regular);
            tips = new ToolTip(components);
            DoubleBuffered = true;
            KeyPreview = true;
            BackColor = Page;
            Icon = SystemIcons.Shield;
            BuildInterface();
            KeyDown += Form_KeyDown;
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            SetCue(filterBox, "account, address, event, or text");
            SetCue(computerBox, "this computer");
            if (started)
                return;
            started = true;
            BeginLoad();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (loadCancel != null)
                loadCancel.Cancel();
            base.OnFormClosing(e);
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            if (loadCancel != null)
                loadCancel.Dispose();
            base.OnFormClosed(e);
        }

        void BuildInterface()
        {
            var header = StackedSection(96, Navy, out var headerBody);
            machineLabel = new Label
            {
                Dock = DockStyle.Right,
                Width = 280,
                TextAlign = ContentAlignment.MiddleRight,
                ForeColor = Color.White,
                Font = CreateFont("Segoe UI", 14F, FontStyle.Bold),
                Text = Environment.MachineName
            };
            var title = new Label
            {
                Dock = DockStyle.Top,
                Height = 34,
                Text = "Server Access Log",
                ForeColor = Color.White,
                Font = titleFont
            };
            subtitleLabel = new Label
            {
                Dock = DockStyle.Fill,
                ForeColor = Color.FromArgb(190, 208, 216),
                Text = "Remote Desktop, SSH, and Windows logon events. The Security log requires an administrator."
            };
            headerBody.Padding = new Padding(20, 14, 20, 10);
            headerBody.Controls.Add(subtitleLabel);
            headerBody.Controls.Add(title);
            headerBody.Controls.Add(machineLabel);

            banner = new Panel
            {
                Dock = DockStyle.Top,
                Height = 52,
                BackColor = Color.FromArgb(255, 244, 214),
                Visible = !IsAdministrator()
            };
            var elevateButton = MakeButton("Restart as administrator", true);
            elevateButton.Dock = DockStyle.Right;
            elevateButton.Width = 210;
            elevateButton.Margin = new Padding(8);
            elevateButton.Click += (sender, args) => RestartElevated();
            var bannerLabel = new Label
            {
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                Padding = new Padding(16, 0, 8, 0),
                ForeColor = Color.FromArgb(122, 91, 0),
                Text = "Not elevated. This computer's Security and Remote Desktop logs need administrator rights. A remote server still works if your account is an administrator there."
            };
            var bannerHost = new Panel { Dock = DockStyle.Fill, BackColor = banner.BackColor, Padding = new Padding(0, 8, 12, 8) };
            bannerHost.Controls.Add(bannerLabel);
            bannerHost.Controls.Add(elevateButton);
            banner.Controls.Add(bannerHost);

            var filters = StackedSection(112, Color.White, out var filterBody);
            filterBody.Padding = new Padding(16, 10, 16, 8);
            var row = new TableLayoutPanel
            {
                Dock = DockStyle.Top,
                Height = 40,
                ColumnCount = 8,
                RowCount = 1
            };
            row.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 160));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
            row.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            rangeBox = new ComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList, Margin = new Padding(0, 6, 12, 6) };
            rangeBox.Items.Add(new RangeChoice("Last hour", 1));
            rangeBox.Items.Add(new RangeChoice("Last 24 hours", 24));
            rangeBox.Items.Add(new RangeChoice("Last 7 days", 24 * 7));
            rangeBox.Items.Add(new RangeChoice("Last 30 days", 24 * 30));
            rangeBox.Items.Add(new RangeChoice("Last 90 days", 24 * 90));
            rangeBox.SelectedIndex = 2;

            computerBox = new TextBox { Dock = DockStyle.Fill, Margin = new Padding(0, 8, 12, 6) };
            maxBox = new NumericUpDown
            {
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 8, 12, 6),
                Minimum = 100,
                Maximum = 20000,
                Increment = 100,
                Value = 2000,
                ThousandsSeparator = true,
                TextAlign = HorizontalAlignment.Right
            };
            refreshButton = MakeButton("Refresh", true);
            refreshButton.Dock = DockStyle.Fill;
            refreshButton.Margin = new Padding(0, 5, 8, 5);
            refreshButton.Click += Refresh_Click;
            exportButton = MakeButton("Export CSV", false);
            exportButton.Dock = DockStyle.Fill;
            exportButton.Margin = new Padding(0, 5, 0, 5);
            exportButton.Click += Export_Click;

            row.Controls.Add(FieldLabel("Range"), 0, 0);
            row.Controls.Add(rangeBox, 1, 0);
            row.Controls.Add(FieldLabel("Computer"), 2, 0);
            row.Controls.Add(computerBox, 3, 0);
            row.Controls.Add(FieldLabel("Max / log"), 4, 0);
            row.Controls.Add(maxBox, 5, 0);
            row.Controls.Add(refreshButton, 6, 0);
            row.Controls.Add(exportButton, 7, 0);

            var checks = new FlowLayoutPanel
            {
                Dock = DockStyle.Top,
                Height = 36,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
                Padding = new Padding(0, 6, 0, 0)
            };
            rdpBox = Check("RDP", true);
            sshBox = Check("SSH", true);
            consoleBox = Check("Console", true);
            networkBox = Check("Network", false);
            failureBox = Check("Failures", true);
            signOutBox = Check("Sign-out", true);
            serviceBox = Check("Service accounts", false);
            checks.Controls.Add(rdpBox);
            checks.Controls.Add(sshBox);
            checks.Controls.Add(consoleBox);
            checks.Controls.Add(networkBox);
            checks.Controls.Add(failureBox);
            checks.Controls.Add(signOutBox);
            checks.Controls.Add(serviceBox);
            filterBody.Controls.Add(checks);
            filterBody.Controls.Add(row);

            tips.SetToolTip(maxBox, "Newest matching events to keep from each log.");
            tips.SetToolTip(computerBox, "Leave blank for this computer. A remote name uses your current account.");
            tips.SetToolTip(rdpBox, "Inbound Remote Desktop, local sessions in that log, and outbound connections from this computer.");
            tips.SetToolTip(sshBox, "OpenSSH event log, sshd.log, and Windows sign-ins from sshd.");
            tips.SetToolTip(consoleBox, "Local sign-in, unlock, and runas.");
            tips.SetToolTip(networkBox, "Network sign-ins, SMB, and file-share access. File-share auditing can be noisy.");
            tips.SetToolTip(failureBox, "Every failed Windows sign-in, of any type.");
            tips.SetToolTip(signOutBox, "User sign-out, Remote Desktop disconnect, and reconnect from the Security log.");
            tips.SetToolTip(serviceBox, "Include service, batch, and machine-account sign-ins.");

            var cards = new Panel { Dock = DockStyle.Top, Height = 84, BackColor = Page, Padding = new Padding(10, 8, 10, 8) };
            var cardTable = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 1, BackColor = Page };
            for (int i = 0; i < 4; i++)
                cardTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
            cardTable.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            cardTable.Controls.Add(MakeCard("RDP events", Teal, out rdpCount), 0, 0);
            cardTable.Controls.Add(MakeCard("SSH events", Color.FromArgb(30, 90, 150), out sshCount), 1, 0);
            cardTable.Controls.Add(MakeCard("Failed attempts", FailFg, out failureCount), 2, 0);
            cardTable.Controls.Add(MakeCard("Source addresses", Navy, out addressCount), 3, 0);
            cards.Controls.Add(cardTable);

            var addressSection = StackedSection(156, Color.White, out var addressBody);
            addressBody.Padding = new Padding(12, 8, 12, 8);
            var addressTable = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            addressTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            addressTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            addressTable.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            succeededList = MakeAddressList();
            failedList = MakeAddressList();
            addressTable.Controls.Add(AddressColumn("Succeeded", Teal, succeededList, out succeededCaption), 0, 0);
            addressTable.Controls.Add(AddressColumn("Failed", FailFg, failedList, out failedCaption), 1, 0);
            addressBody.Controls.Add(addressTable);
            tips.SetToolTip(succeededList, "Inbound connections and successful sign-ins. Click an address to filter the grid.");
            tips.SetToolTip(failedList, "Failed sign-ins. Click an address to filter the grid.");

            var quick = StackedSection(48, Color.White, out var quickBody);
            quickBody.Padding = new Padding(16, 8, 16, 8);
            showingLabel = new Label
            {
                Dock = DockStyle.Right,
                Width = 180,
                TextAlign = ContentAlignment.MiddleRight,
                ForeColor = Muted,
                Text = "0 of 0"
            };
            filterBox = new TextBox { Dock = DockStyle.Left, Width = 320 };
            var filterLabel = FieldLabel("Filter");
            filterLabel.Dock = DockStyle.Left;
            filterLabel.Width = 48;
            directionBox = new ComboBox
            {
                Dock = DockStyle.Left,
                Width = 110,
                DropDownStyle = ComboBoxStyle.DropDownList,
                Margin = new Padding(12, 0, 0, 0)
            };
            directionBox.Items.Add("All");
            directionBox.Items.Add("In");
            directionBox.Items.Add("Out");
            directionBox.Items.Add("Local");
            directionBox.SelectedIndex = 0;
            var directionLabel = FieldLabel("Direction");
            directionLabel.AutoSize = false;
            directionLabel.Dock = DockStyle.Left;
            directionLabel.Width = 92;
            directionLabel.TextAlign = ContentAlignment.MiddleLeft;
            directionLabel.Padding = new Padding(16, 0, 0, 0);
            quickBody.Controls.Add(showingLabel);
            quickBody.Controls.Add(directionBox);
            quickBody.Controls.Add(directionLabel);
            quickBody.Controls.Add(filterBox);
            quickBody.Controls.Add(filterLabel);
            filterBox.TextChanged += (sender, args) => ApplyFilter();
            directionBox.SelectedIndexChanged += (sender, args) => ApplyFilter();
            tips.SetToolTip(directionBox, "In: someone reached this computer. Out: this computer opened Remote Desktop to another server. Local: a sign-in on this computer.");

            var split = new SplitContainer
            {
                Dock = DockStyle.Fill,
                Orientation = Orientation.Horizontal,
                SplitterWidth = 6,
                BackColor = Page
            };

            var gridFrame = new Panel { Dock = DockStyle.Fill, BackColor = Line, Padding = new Padding(1, 1, 1, 0) };
            grid = new DataGridView { Dock = DockStyle.Fill };
            ConfigureGrid();
            gridFrame.Controls.Add(grid);
            split.Panel1.Controls.Add(gridFrame);

            var detailFrame = new Panel { Dock = DockStyle.Fill, BackColor = Line, Padding = new Padding(1, 0, 1, 1) };
            var detail = new Panel { Dock = DockStyle.Fill, BackColor = Color.White, Padding = new Padding(12, 8, 12, 8) };
            var copyButton = MakeButton("Copy", false);
            copyButton.Dock = DockStyle.Right;
            copyButton.Width = 80;
            copyButton.Click += (sender, args) => CopyDetail();
            var detailLabel = new Label
            {
                Dock = DockStyle.Left,
                AutoSize = true,
                Font = boldFont,
                Text = "Full event",
                Padding = new Padding(0, 6, 0, 0)
            };
            var detailBar = new Panel { Dock = DockStyle.Top, Height = 32 };
            detailBar.Controls.Add(detailLabel);
            detailBar.Controls.Add(copyButton);
            detailBox = new TextBox
            {
                Dock = DockStyle.Fill,
                Multiline = true,
                ReadOnly = true,
                WordWrap = true,
                ScrollBars = ScrollBars.Vertical,
                BorderStyle = BorderStyle.None,
                BackColor = Color.White,
                Font = detailFont,
                HideSelection = false,
                Text = "Select a row to read the full event."
            };
            detail.Controls.Add(detailBox);
            detail.Controls.Add(detailBar);
            detailFrame.Controls.Add(detail);
            split.Panel2.Controls.Add(detailFrame);

            var status = new StatusStrip
            {
                BackColor = Page,
                SizingGrip = true,
                Renderer = new ToolStripProfessionalRenderer(new FlatStatusColors())
            };
            statusLabel = new ToolStripStatusLabel
            {
                Spring = true,
                TextAlign = ContentAlignment.MiddleLeft,
                ForeColor = Muted,
                Text = "Ready."
            };
            elevationLabel = new ToolStripStatusLabel
            {
                Text = IsAdministrator() ? "Administrator" : "Not elevated",
                ForeColor = IsAdministrator() ? Teal : FailFg
            };
            status.Items.Add(statusLabel);
            status.Items.Add(elevationLabel);

            // Dock order: the last control added claims its edge first.
            Controls.Add(split);
            Controls.Add(status);
            Controls.Add(quick);
            Controls.Add(addressSection);
            Controls.Add(cards);
            Controls.Add(filters);
            Controls.Add(banner);
            Controls.Add(header);

            Shown += (sender, args) =>
            {
                try
                {
                    split.Panel1MinSize = 120;
                    split.Panel2MinSize = 90;
                    int room = split.Height - split.Panel2MinSize - split.SplitterWidth;
                    if (room > split.Panel1MinSize)
                        split.SplitterDistance = Math.Max(split.Panel1MinSize, split.Height - 190);
                }
                catch (InvalidOperationException)
                {
                }
            };
        }

        void ConfigureGrid()
        {
            grid.AutoGenerateColumns = false;
            grid.AllowUserToAddRows = false;
            grid.AllowUserToDeleteRows = false;
            grid.AllowUserToOrderColumns = true;
            grid.AllowUserToResizeRows = false;
            grid.ReadOnly = true;
            grid.MultiSelect = false;
            grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            grid.RowHeadersVisible = false;
            grid.BackgroundColor = Color.White;
            grid.BorderStyle = BorderStyle.None;
            grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
            grid.GridColor = Line;
            grid.EnableHeadersVisualStyles = false;
            grid.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None;
            grid.ColumnHeadersHeight = 34;
            grid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
            grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(236, 240, 244);
            grid.ColumnHeadersDefaultCellStyle.ForeColor = Ink;
            grid.ColumnHeadersDefaultCellStyle.Font = boldFont;
            grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = Color.FromArgb(236, 240, 244);
            grid.DefaultCellStyle.ForeColor = Ink;
            grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(207, 226, 236);
            grid.DefaultCellStyle.SelectionForeColor = Ink;
            grid.DefaultCellStyle.Padding = new Padding(4, 0, 4, 0);
            grid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(248, 250, 252);
            grid.RowTemplate.Height = 26;
            grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            grid.ClipboardCopyMode = DataGridViewClipboardCopyMode.EnableAlwaysIncludeHeaderText;
            grid.ShowCellToolTips = true;
            EnableDoubleBuffer(grid);

            AddColumn("Time", "Time", 16, 140, "yyyy-MM-dd HH:mm:ss");
            AddColumn("Source", "Source", 10, 80, null);
            var direction = AddColumn("Direction", "Direction", 9, 78, null);
            direction.HeaderCell.ToolTipText = "In: someone reached this computer. Out: this computer opened Remote Desktop to another server. Local: a sign-in on this computer.";
            AddColumn("Result", "Result", 10, 80, null);
            AddColumn("User", "Account", 16, 120, null);
            AddColumn("Address", "Address", 14, 120, null);
            var portColumn = AddColumn("Port", "Port", 8, 64, null);
            portColumn.DefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleRight;
            portColumn.HeaderCell.Style.Alignment = DataGridViewContentAlignment.MiddleRight;
            portColumn.HeaderCell.ToolTipText = "Source port of the remote computer. Blank when Windows did not record one.";
            var actionColumn = AddColumn("Action", "Action", 18, 150, null);
            actionColumn.HeaderCell.ToolTipText = "What the attempt was doing, such as an NTLM or SMB sign-in, a file share, Remote Desktop, or SSH.";
            AddColumn("LogonType", "Logon type", 14, 110, null);
            var eventColumn = AddColumn("EventId", "Event", 8, 70, null);
            eventColumn.DefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleRight;
            eventColumn.HeaderCell.Style.Alignment = DataGridViewContentAlignment.MiddleRight;
            AddColumn("Channel", "Log", 12, 100, null);
            AddColumn("Summary", "Details", 30, 180, null);
            var message = AddColumn("Message", "Message", 1, 20, null);
            message.Visible = false;

            grid.CellFormatting += Grid_CellFormatting;
            grid.SelectionChanged += (sender, args) => ShowSelectedDetail();
            grid.CellDoubleClick += Grid_CellDoubleClick;
        }

        DataGridViewTextBoxColumn AddColumn(string name, string header, float fill, int min, string format)
        {
            var column = new DataGridViewTextBoxColumn
            {
                Name = name,
                DataPropertyName = name,
                HeaderText = header,
                FillWeight = fill,
                MinimumWidth = min,
                SortMode = DataGridViewColumnSortMode.Automatic,
                ReadOnly = true
            };
            if (format != null)
                column.DefaultCellStyle.Format = format;
            grid.Columns.Add(column);
            return column;
        }

        void Refresh_Click(object sender, EventArgs e)
        {
            if (busy)
            {
                if (loadCancel != null)
                    loadCancel.Cancel();
                return;
            }
            BeginLoad();
        }

        void Form_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.F5)
            {
                e.Handled = true;
                e.SuppressKeyPress = true;
                Refresh_Click(sender, e);
            }
        }

        async void BeginLoad()
        {
            if (busy)
                return;
            if (!rdpBox.Checked && !sshBox.Checked && !consoleBox.Checked && !networkBox.Checked
                && !failureBox.Checked && !signOutBox.Checked && !serviceBox.Checked)
            {
                MessageBox.Show(this, "Select at least one log type.", "Server Access Log", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            generation++;
            int gen = generation;
            if (loadCancel != null)
                loadCancel.Cancel();
            loadCancel = new CancellationTokenSource();
            var token = loadCancel.Token;
            SetBusy(true);
            statusLabel.Text = "Reading access logs...";
            var started = DateTime.UtcNow;
            try
            {
                var query = ReadQuery();
                var progress = new Progress<string>(message =>
                {
                    try
                    {
                        if (gen != generation || IsDisposed)
                            return;
                        statusLabel.Text = message;
                    }
                    catch (InvalidOperationException)
                    {
                    }
                });
                var result = await Task.Run(() => AccessLogService.Load(query, progress, token), token);
                if (gen != generation || IsDisposed)
                    return;
                Bind(result);
                ShowStatus(result, started);
            }
            catch (OperationCanceledException)
            {
                if (gen == generation && !IsDisposed)
                    statusLabel.Text = "Canceled.";
            }
            catch (Exception ex)
            {
                if (gen != generation || IsDisposed)
                    return;
                statusLabel.Text = "The logs could not be read.";
                MessageBox.Show(this, ex.Message, "Server Access Log", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                if (gen == generation && !IsDisposed)
                    SetBusy(false);
            }
        }

        AccessQuery ReadQuery()
        {
            var choice = rangeBox.SelectedItem as RangeChoice;
            return new AccessQuery
            {
                Hours = choice == null ? 24 * 7 : choice.Hours,
                MaxEvents = (int)maxBox.Value,
                Computer = computerBox.Text.Trim(),
                Rdp = rdpBox.Checked,
                Ssh = sshBox.Checked,
                Console = consoleBox.Checked,
                Network = networkBox.Checked,
                Failures = failureBox.Checked,
                SignOut = signOutBox.Checked,
                ServiceAccounts = serviceBox.Checked
            };
        }

        void Bind(AccessLogResult result)
        {
            machineLabel.Text = result.Computer;
            Text = "Server Access Log - " + result.Computer;

            table = new DataTable();
            table.Columns.Add("Time", typeof(DateTime));
            table.Columns.Add("Source", typeof(string));
            table.Columns.Add("Direction", typeof(string));
            table.Columns.Add("Result", typeof(string));
            table.Columns.Add("User", typeof(string));
            table.Columns.Add("Address", typeof(string));
            table.Columns.Add("Port", typeof(string));
            table.Columns.Add("Action", typeof(string));
            table.Columns.Add("LogonType", typeof(string));
            table.Columns.Add("EventId", typeof(int));
            table.Columns.Add("Channel", typeof(string));
            table.Columns.Add("Summary", typeof(string));
            table.Columns.Add("Message", typeof(string));

            foreach (var ev in result.Events)
            {
                table.Rows.Add(
                    ev.Time,
                    ev.Source ?? "",
                    ev.Direction ?? "",
                    ev.Result ?? "",
                    ev.User ?? "",
                    ev.Address ?? "",
                    ev.Port ?? "",
                    ev.Action ?? "",
                    ev.LogonType ?? "",
                    ev.EventId,
                    ev.Channel ?? "",
                    ev.Summary ?? "",
                    ev.Message ?? "");
            }

            view = table.DefaultView;
            view.Sort = "Time DESC";
            grid.DataSource = view;
            ApplyFilter();
            if (grid.Rows.Count > 0)
            {
                grid.Rows[0].Selected = true;
                grid.Focus();
            }
            else
            {
                ShowSelectedDetail();
            }
        }

        void ApplyFilter()
        {
            if (view == null)
                return;
            string filter = "";
            var text = filterBox.Text.Trim();
            if (text.Length > 0)
            {
                string escaped = EscapeLike(text);
                filter =
                    "(Source LIKE '%" + escaped + "%'" +
                    " OR Direction LIKE '%" + escaped + "%'" +
                    " OR Result LIKE '%" + escaped + "%'" +
                    " OR User LIKE '%" + escaped + "%'" +
                    " OR Address LIKE '%" + escaped + "%'" +
                    " OR Port LIKE '%" + escaped + "%'" +
                    " OR Action LIKE '%" + escaped + "%'" +
                    " OR LogonType LIKE '%" + escaped + "%'" +
                    " OR Channel LIKE '%" + escaped + "%'" +
                    " OR Summary LIKE '%" + escaped + "%'" +
                    " OR Message LIKE '%" + escaped + "%'" +
                    " OR Convert(EventId, 'System.String') LIKE '%" + escaped + "%')";
            }
            var direction = directionBox.SelectedItem as string;
            if (direction == "In" || direction == "Out" || direction == "Local")
            {
                if (filter.Length > 0)
                    filter += " AND ";
                filter += "Direction = '" + direction + "'";
            }
            try
            {
                view.RowFilter = filter;
            }
            catch (EvaluateException)
            {
                view.RowFilter = "";
            }
            catch (SyntaxErrorException)
            {
                view.RowFilter = "";
            }
            UpdateSummary();
            ShowSelectedDetail();
        }

        void UpdateSummary()
        {
            int rdp = 0;
            int ssh = 0;
            int failed = 0;
            var addresses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var succeeded = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var failedAddresses = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            if (view != null)
            {
                foreach (DataRowView row in view)
                {
                    var source = Convert.ToString(row["Source"]);
                    var result = Convert.ToString(row["Result"]);
                    var direction = Convert.ToString(row["Direction"]);
                    if (source == "RDP") rdp++;
                    else if (source == "SSH") ssh++;
                    if (result == "Failure") failed++;
                    var host = HostOnly(Convert.ToString(row["Address"]));
                    if (host.Length == 0 || host.Equals("local", StringComparison.OrdinalIgnoreCase))
                        continue;
                    addresses.Add(host);
                    if (result == "Failure")
                        AddCount(failedAddresses, host);
                    else if (direction == "In" && (result == "Success" || result == "Connect"))
                        AddCount(succeeded, host);
                }
            }
            ShowAddresses(succeededList, succeededCaption, "Succeeded", succeeded);
            ShowAddresses(failedList, failedCaption, "Failed", failedAddresses);
            rdpCount.Text = rdp.ToString("N0");
            sshCount.Text = ssh.ToString("N0");
            failureCount.Text = failed.ToString("N0");
            addressCount.Text = addresses.Count.ToString("N0");
            int total = table == null ? 0 : table.Rows.Count;
            int shown = view == null ? 0 : view.Count;
            showingLabel.Text = shown.ToString("N0") + " of " + total.ToString("N0");
        }

        void ShowStatus(AccessLogResult result, DateTime startedUtc)
        {
            var seconds = (DateTime.UtcNow - startedUtc).TotalSeconds;
            var text = "Loaded " + result.Events.Count.ToString("N0")
                + " events in " + seconds.ToString("0.0")
                + " seconds from " + result.Computer + ".";
            if (result.Truncated)
                text += " Some logs hit the event limit.";
            if (result.Notes.Count > 0)
                text += " " + result.Notes[0];
            if (result.Notes.Count > 1)
                text += " (" + (result.Notes.Count - 1).ToString(CultureInfo.CurrentCulture) + " more; hover for the full list)";
            statusLabel.Text = text;
            statusLabel.ToolTipText = result.Notes.Count == 0
                ? text
                : string.Join(Environment.NewLine, result.Notes.ToArray());
        }

        void ShowSelectedDetail()
        {
            if (grid.CurrentRow == null || grid.CurrentRow.IsNewRow || grid.CurrentRow.Cells["Message"].Value == null)
            {
                detailBox.Text = view == null || view.Count == 0
                    ? "No events matched. Widen the time range or clear the filter."
                    : "Select a row to read the full event.";
                return;
            }
            detailBox.Text = Convert.ToString(grid.CurrentRow.Cells["Message"].Value);
        }

        void Grid_CellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
        {
            if (e.RowIndex < 0 || e.ColumnIndex < 0)
                return;
            var result = Convert.ToString(grid.Rows[e.RowIndex].Cells["Result"].Value);
            bool selected = grid.Rows[e.RowIndex].Selected;
            if (!selected && result == "Failure")
            {
                e.CellStyle.BackColor = FailBg;
                e.CellStyle.ForeColor = FailFg;
                if (grid.Columns[e.ColumnIndex].Name == "Result")
                    e.CellStyle.Font = boldFont;
            }
            else if (!selected && (result == "Connect" || result == "Warning"))
            {
                e.CellStyle.BackColor = ConnectBg;
            }

            if (!selected && result != "Failure" && grid.Columns[e.ColumnIndex].Name == "Direction")
            {
                var direction = Convert.ToString(e.Value);
                if (direction == "In")
                    e.CellStyle.ForeColor = Teal;
                else if (direction == "Out")
                    e.CellStyle.ForeColor = Color.FromArgb(30, 78, 160);
                else
                    e.CellStyle.ForeColor = Muted;
                e.CellStyle.Font = boldFont;
            }

            if (grid.Columns[e.ColumnIndex].Name == "EventId")
            {
                int id;
                if (e.Value == null || e.Value == DBNull.Value || !int.TryParse(Convert.ToString(e.Value), out id) || id == 0)
                {
                    e.Value = "";
                    e.FormattingApplied = true;
                }
            }
        }

        void Grid_CellDoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex < 0)
                return;
            var text = Convert.ToString(grid.Rows[e.RowIndex].Cells["Message"].Value);
            var caption = Convert.ToString(grid.Rows[e.RowIndex].Cells["Summary"].Value);
            if (string.IsNullOrWhiteSpace(caption))
                caption = "Event detail";

            using (var dialog = new Form())
            {
                dialog.Text = caption;
                dialog.StartPosition = FormStartPosition.CenterParent;
                dialog.Size = new Size(860, 640);
                dialog.MinimizeBox = false;
                dialog.ShowIcon = false;
                dialog.Font = Font;
                dialog.BackColor = Color.White;
                var box = new TextBox
                {
                    Multiline = true,
                    ReadOnly = true,
                    Dock = DockStyle.Fill,
                    ScrollBars = ScrollBars.Both,
                    WordWrap = false,
                    BorderStyle = BorderStyle.None,
                    Text = text,
                    Font = detailFont,
                    BackColor = Color.White,
                    HideSelection = false
                };
                dialog.Controls.Add(box);
                dialog.ShowDialog(this);
            }
        }

        void Export_Click(object sender, EventArgs e)
        {
            if (view == null || view.Count == 0)
            {
                MessageBox.Show(this, "There are no events to export.", "Server Access Log", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            using (var dialog = new SaveFileDialog())
            {
                dialog.Filter = "CSV files (*.csv)|*.csv";
                dialog.FileName = "AccessLog-" + SafeFileName(machineLabel.Text) + "-" + DateTime.Now.ToString("yyyyMMdd-HHmm") + ".csv";
                dialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                if (dialog.ShowDialog(this) != DialogResult.OK)
                    return;

                var sb = new StringBuilder();
                sb.AppendLine("Time,Source,Direction,Result,Account,Address,Port,Action,Logon type,Event,Log,Details,Message");
                foreach (DataRowView row in view)
                {
                    sb.Append(Csv(row["Time"] is DateTime ? ((DateTime)row["Time"]).ToString("yyyy-MM-dd HH:mm:ss") : "")).Append(',');
                    sb.Append(Csv(Convert.ToString(row["Source"]))).Append(',');
                    sb.Append(Csv(Convert.ToString(row["Direction"]))).Append(',');
                    sb.Append(Csv(Convert.ToString(row["Result"]))).Append(',');
                    sb.Append(Csv(Convert.ToString(row["User"]))).Append(',');
                    sb.Append(Csv(Convert.ToString(row["Address"]))).Append(',');
                    sb.Append(Csv(Convert.ToString(row["Port"]))).Append(',');
                    sb.Append(Csv(Convert.ToString(row["Action"]))).Append(',');
                    sb.Append(Csv(Convert.ToString(row["LogonType"]))).Append(',');
                    sb.Append(Csv(Convert.ToString(row["EventId"]))).Append(',');
                    sb.Append(Csv(Convert.ToString(row["Channel"]))).Append(',');
                    sb.Append(Csv(Convert.ToString(row["Summary"]))).Append(',');
                    sb.Append(Csv(Convert.ToString(row["Message"])));
                    sb.AppendLine();
                }
                System.IO.File.WriteAllText(dialog.FileName, sb.ToString(), new UTF8Encoding(true));
                statusLabel.Text = "Exported " + view.Count.ToString("N0") + " events to " + dialog.FileName;
            }
        }

        void CopyDetail()
        {
            if (string.IsNullOrEmpty(detailBox.Text) || detailBox.Text.StartsWith("Select a row", StringComparison.Ordinal) || detailBox.Text.StartsWith("No events matched", StringComparison.Ordinal))
                return;
            try
            {
                Clipboard.SetText(detailBox.Text);
                statusLabel.Text = "Copied the event to the clipboard.";
            }
            catch (ExternalException ex)
            {
                MessageBox.Show(this, ex.Message, "Server Access Log", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        void RestartElevated()
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = Application.ExecutablePath,
                    UseShellExecute = true,
                    Verb = "runas"
                });
                Close();
            }
            catch (Win32Exception ex)
            {
                if (ex.NativeErrorCode == 1223)
                    return;
                MessageBox.Show(this, ex.Message, "Server Access Log", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        void SetBusy(bool value)
        {
            busy = value;
            UseWaitCursor = value;
            refreshButton.Text = value ? "Cancel" : "Refresh";
            refreshButton.BackColor = value ? Color.FromArgb(122, 48, 42) : Teal;
            refreshButton.FlatAppearance.BorderColor = refreshButton.BackColor;
            refreshButton.FlatAppearance.MouseOverBackColor = value ? Color.FromArgb(150, 64, 56) : Color.FromArgb(16, 140, 136);
            exportButton.Enabled = !value;
            rangeBox.Enabled = !value;
            computerBox.Enabled = !value;
            maxBox.Enabled = !value;
            rdpBox.Enabled = !value;
            sshBox.Enabled = !value;
            consoleBox.Enabled = !value;
            networkBox.Enabled = !value;
            failureBox.Enabled = !value;
            signOutBox.Enabled = !value;
            serviceBox.Enabled = !value;
        }

        static Panel StackedSection(int height, Color back, out Panel body)
        {
            var outer = new Panel
            {
                Dock = DockStyle.Top,
                Height = height,
                BackColor = Line,
                Padding = new Padding(0, 0, 0, 1)
            };
            body = new Panel { Dock = DockStyle.Fill, BackColor = back };
            outer.Controls.Add(body);
            return outer;
        }

        static Label FieldLabel(string text)
        {
            return new Label
            {
                Text = text,
                AutoSize = true,
                Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 8, 8, 0),
                ForeColor = Ink
            };
        }

        CheckBox Check(string text, bool value)
        {
            return new CheckBox
            {
                Text = text,
                Checked = value,
                AutoSize = true,
                Margin = new Padding(0, 4, 16, 0),
                ForeColor = Ink
            };
        }

        static Panel MakeCard(string caption, Color valueColor, out Label value)
        {
            var border = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Line,
                Padding = new Padding(1),
                Margin = new Padding(6, 0, 6, 0)
            };
            var inner = new Panel { Dock = DockStyle.Fill, BackColor = Color.White, Padding = new Padding(14, 6, 8, 6) };
            value = new Label
            {
                Text = "0",
                Dock = DockStyle.Top,
                Height = 32,
                Font = CreateFont("Segoe UI", 18F, FontStyle.Bold),
                ForeColor = valueColor
            };
            var cap = new Label
            {
                Text = caption,
                Dock = DockStyle.Bottom,
                Height = 18,
                ForeColor = Muted
            };
            inner.Controls.Add(cap);
            inner.Controls.Add(value);
            border.Controls.Add(inner);
            return border;
        }

        Button MakeButton(string text, bool primary)
        {
            var button = new Button
            {
                Text = text,
                FlatStyle = FlatStyle.Flat,
                UseVisualStyleBackColor = false,
                Cursor = Cursors.Hand,
                ForeColor = primary ? Color.White : Ink,
                BackColor = primary ? Teal : Color.White
            };
            button.FlatAppearance.BorderColor = primary ? Teal : Line;
            button.FlatAppearance.BorderSize = 1;
            button.FlatAppearance.MouseOverBackColor = primary ? Color.FromArgb(16, 140, 136) : Color.FromArgb(244, 247, 248);
            return button;
        }

        static void EnableDoubleBuffer(DataGridView view)
        {
            typeof(DataGridView).InvokeMember(
                "DoubleBuffered",
                BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.SetProperty,
                null,
                view,
                new object[] { true });
        }

        static void SetCue(TextBox box, string text)
        {
            if (box.IsHandleCreated)
                SendMessage(box.Handle, 0x1501, (IntPtr)1, text);
        }

        static bool IsAdministrator()
        {
            try
            {
                using (var identity = WindowsIdentity.GetCurrent())
                    return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (Exception)
            {
                return false;
            }
        }

        static void AddCount(Dictionary<string, int> counts, string host)
        {
            int count;
            counts.TryGetValue(host, out count);
            counts[host] = count + 1;
        }

        void ShowAddresses(ListView list, Label caption, string title, Dictionary<string, int> counts)
        {
            if (list == null || caption == null)
                return;
            caption.Text = title + "  " + counts.Count.ToString("N0");
            var rows = new List<KeyValuePair<string, int>>(counts);
            rows.Sort((a, b) =>
            {
                int byCount = b.Value.CompareTo(a.Value);
                if (byCount != 0)
                    return byCount;
                return string.Compare(a.Key, b.Key, StringComparison.OrdinalIgnoreCase);
            });

            fillingAddresses = true;
            list.BeginUpdate();
            try
            {
                list.Items.Clear();
                foreach (var row in rows)
                {
                    var item = new ListViewItem(row.Key);
                    item.SubItems.Add(row.Value.ToString("N0"));
                    list.Items.Add(item);
                }
            }
            finally
            {
                list.EndUpdate();
                fillingAddresses = false;
            }
        }

        void AddressList_Selected(object sender, EventArgs e)
        {
            if (fillingAddresses)
                return;
            var list = sender as ListView;
            if (list == null || list.SelectedItems.Count == 0)
                return;
            string ip = list.SelectedItems[0].Text;
            if (!filterBox.Text.Equals(ip, StringComparison.OrdinalIgnoreCase))
                filterBox.Text = ip;
        }

        ListView MakeAddressList()
        {
            var list = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                BorderStyle = BorderStyle.None,
                HeaderStyle = ColumnHeaderStyle.Nonclickable,
                HideSelection = false,
                MultiSelect = false
            };
            list.Columns.Add("Address", 220);
            list.Columns.Add("Count", 72, HorizontalAlignment.Right);
            list.Resize += (sender, args) =>
            {
                int addressWidth = list.ClientSize.Width - list.Columns[1].Width - SystemInformation.VerticalScrollBarWidth;
                if (addressWidth < 80)
                    addressWidth = 80;
                list.Columns[0].Width = addressWidth;
            };
            list.SelectedIndexChanged += AddressList_Selected;
            return list;
        }

        Panel AddressColumn(string title, Color color, ListView list, out Label caption)
        {
            var panel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(4, 0, 4, 0) };
            caption = new Label
            {
                Dock = DockStyle.Top,
                Height = 22,
                Font = boldFont,
                ForeColor = color,
                Text = title + "  0"
            };
            panel.Controls.Add(list);
            panel.Controls.Add(caption);
            return panel;
        }

        static string HostOnly(string address)
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
            int first = address.IndexOf(':');
            int last = address.LastIndexOf(':');
            if (first > 0 && first == last)
                return address.Substring(0, first);
            return address;
        }

        static string EscapeLike(string value)
        {
            var sb = new StringBuilder(value.Length);
            foreach (var ch in value)
            {
                switch (ch)
                {
                    case ']':
                    case '[':
                    case '%':
                    case '*':
                        sb.Append('[').Append(ch).Append(']');
                        break;
                    case '\'':
                        sb.Append("''");
                        break;
                    default:
                        sb.Append(ch);
                        break;
                }
            }
            return sb.ToString();
        }

        static string Csv(string value)
        {
            if (value == null)
                value = "";
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        }

        static string SafeFileName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return "server";
            foreach (var ch in System.IO.Path.GetInvalidFileNameChars())
                name = name.Replace(ch, '-');
            return name;
        }

        static Font CreateFont(string family, float size, FontStyle style)
        {
            try
            {
                return new Font(family, size, style);
            }
            catch (ArgumentException)
            {
                return new Font(SystemFonts.MessageBoxFont.FontFamily, size, style);
            }
        }

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, string lParam);

        sealed class RangeChoice
        {
            public RangeChoice(string label, int hours)
            {
                Label = label;
                Hours = hours;
            }

            public string Label { get; private set; }
            public int Hours { get; private set; }
            public override string ToString()
            {
                return Label;
            }
        }

        sealed class FlatStatusColors : ProfessionalColorTable
        {
            static readonly Color Bar = Color.FromArgb(241, 244, 247);
            public override Color ToolStripGradientBegin { get { return Bar; } }
            public override Color ToolStripGradientMiddle { get { return Bar; } }
            public override Color ToolStripGradientEnd { get { return Bar; } }
            public override Color StatusStripGradientBegin { get { return Bar; } }
            public override Color StatusStripGradientEnd { get { return Bar; } }
        }
    }
}
