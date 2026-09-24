using Mtkey.Core;

namespace Mtkey;

/// <summary>The whole workbench: pick a cipher, fill its parameters (roll the
/// dice for anything random), and watch the output update live.</summary>
internal sealed class MainForm : Form
{
    private static readonly Color Ink = Color.FromArgb(31, 33, 40);
    private static readonly Color Muted = Color.FromArgb(96, 100, 110);
    private static readonly Color Accent = Color.FromArgb(79, 70, 229);
    private static readonly Color NoteGreen = Color.FromArgb(22, 101, 52);
    private static readonly Color WarnOrange = Color.FromArgb(154, 52, 18);
    private static readonly Color ErrorRed = Color.FromArgb(185, 28, 28);
    private static readonly Color SoftBg = Color.FromArgb(250, 250, 252);

    private readonly SearchDropDown _selector = new() { Dock = DockStyle.Fill };
    private readonly Button _wikiButton = NewButton("🔗 Learn more");
    private readonly Label _blurb = new();
    private readonly Label _learn = new();
    private readonly RadioButton _encodeRadio = NewRadio("Encode");
    private readonly RadioButton _decodeRadio = NewRadio("Decode");
    private readonly Label _oneWayLabel = new();
    private readonly TableLayoutPanel _paramsTable = new();
    private readonly TextBox _input = NewMonoBox();
    private readonly TextBox _output = NewMonoBox(readOnly: true);
    private readonly Label _status = new();
    private readonly System.Windows.Forms.Timer _debounce = new() { Interval = 220 };
    private readonly ToolTip _tips = new();

    private CipherMethod _method = Registry.All[0];
    private CipherDirection _direction = CipherDirection.Encode;
    private readonly Dictionary<string, Control> _fieldControls = new();
    private readonly Dictionary<string, Label> _fieldStatus = new();
    private readonly Dictionary<string, FieldSpec> _fieldSpecs = new();

    /// <param name="demoInput">Pre-fills the input box, used by --demo.</param>
    public MainForm(string? demoInput = null)
    {
        Text = "MTKey";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(880, 640);
        ClientSize = new Size(980, 760);
        Font = new Font("Segoe UI", 9.75f);
        BackColor = Color.White;
        ForeColor = Ink;

        BuildHeader();
        BuildSelectorRow();
        BuildInfoPanel();
        BuildDirectionRow();
        BuildParamsPanel();
        BuildIoArea();
        BuildStatus();

        _selector.Items = Registry.All.ToList();
        _selector.MethodPicked += m => SwitchMethod(m);
        _wikiButton.Click += (_, _) => OpenWiki();

        _debounce.Tick += (_, _) => { _debounce.Stop(); ValidateLive(); ProcessNow(); };

        SwitchMethod(Registry.All[0]);

        if (demoInput != null)
        {
            _input.Text = demoInput;
            Schedule();
        }
    }

    // ------------------------------------------------------------ layout

    private void BuildHeader()
    {
        var panel = new Panel { Dock = DockStyle.Top, Height = 66, Padding = new Padding(18, 12, 18, 8) };
        var title = new Label
        {
            Text = "MTKey",
            Font = new Font("Segoe UI Semibold", 16f),
            ForeColor = Color.FromArgb(49, 46, 129),
            AutoSize = true,
            Location = new Point(18, 10),
        };
        var subtitle = new Label
        {
            Text = "a crypto playground: encode, decode, hash, sign, and actually learn how each one works",
            Font = new Font("Segoe UI", 9.75f),
            ForeColor = Muted,
            AutoSize = true,
            Location = new Point(108, 24),
        };
        panel.Controls.Add(title);
        panel.Controls.Add(subtitle);
        Controls.Add(panel);
    }

    private void BuildSelectorRow()
    {
        var panel = new Panel { Dock = DockStyle.Top, Height = 52, Padding = new Padding(18, 8, 18, 8) };
        var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2 };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 170));
        grid.Controls.Add(_selector, 0, 0);
        _wikiButton.AutoSize = false;
        _wikiButton.Dock = DockStyle.Fill;
        _wikiButton.Margin = new Padding(10, 2, 0, 2);
        _wikiButton.TextAlign = ContentAlignment.MiddleCenter;
        _wikiButton.Font = new Font("Segoe UI Emoji", 9.75f);
        grid.Controls.Add(_wikiButton, 1, 0);
        panel.Controls.Add(grid);
        Controls.Add(panel);
    }

    private void BuildInfoPanel()
    {
        var panel = new Panel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(18, 4, 18, 8), BackColor = SoftBg };
        _blurb.Dock = DockStyle.Top;
        _blurb.Font = new Font("Segoe UI Semibold", 10.5f);
        _blurb.ForeColor = Ink;
        _blurb.AutoSize = true;
        _blurb.Padding = new Padding(0, 4, 0, 0);

        _learn.Dock = DockStyle.Top;
        _learn.Font = new Font("Segoe UI", 9.25f);
        _learn.ForeColor = Muted;
        _learn.AutoSize = true;
        _learn.MaximumSize = new Size(940, 0);
        _learn.Padding = new Padding(0, 4, 0, 6);

        panel.Controls.Add(_learn);
        panel.Controls.Add(_blurb);
        Controls.Add(panel);
    }

    private void BuildDirectionRow()
    {
        var panel = new Panel { Dock = DockStyle.Top, Height = 40, Padding = new Padding(18, 4, 18, 4) };
        _encodeRadio.CheckedChanged += (_, _) => DirectionChanged();
        _decodeRadio.CheckedChanged += (_, _) => DirectionChanged();
        _oneWayLabel.AutoSize = true;
        _oneWayLabel.ForeColor = Muted;
        _oneWayLabel.Padding = new Padding(4, 5, 0, 0);
        panel.Controls.Add(_encodeRadio);
        panel.Controls.Add(_decodeRadio);
        panel.Controls.Add(_oneWayLabel);
        _decodeRadio.Location = new Point(140, 8);
        _encodeRadio.Location = new Point(16, 8);
        _oneWayLabel.Location = new Point(16, 8);
        Controls.Add(panel);
    }

    private void BuildParamsPanel()
    {
        _paramsTable.Dock = DockStyle.Top;
        _paramsTable.AutoSize = true;
        _paramsTable.Padding = new Padding(10, 4, 10, 8);
        _paramsTable.ColumnCount = 4;
        _paramsTable.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 170));
        _paramsTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        _paramsTable.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 42));
        _paramsTable.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 250));
        Controls.Add(_paramsTable);
    }

    private void BuildIoArea()
    {
        var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Padding = new Padding(16, 4, 16, 4) };
        grid.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
        grid.RowStyles.Add(new RowStyle(SizeType.Percent, 50));

        grid.Controls.Add(BuildOneSide("Input", _input, buttons: false), 0, 0);
        grid.Controls.Add(BuildOneSide("Output", _output, buttons: true), 0, 1);
        Controls.Add(grid);
    }

    private Control BuildOneSide(string caption, TextBox box, bool buttons)
    {
        var side = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = new Padding(0, 6, 0, 6) };
        side.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        side.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var head = new TableLayoutPanel { Dock = DockStyle.Top, ColumnCount = 2, AutoSize = true, Margin = new Padding(0, 0, 0, 4) };
        head.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        head.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        var label = new Label
        {
            Text = caption,
            Font = new Font("Segoe UI Semibold", 10.5f),
            ForeColor = Ink,
            AutoSize = true,
            Margin = new Padding(0, 4, 0, 4),
        };
        head.Controls.Add(label, 0, 0);

        if (buttons)
        {
            var actions = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill, AutoSize = true };
            var copy = NewButton("📋 Copy");
            var use = NewButton("↩ Use as input");
            var clear = NewButton("🧹 Clear");
            copy.Click += (_, _) => CopyOutput();
            use.Click += (_, _) => { _input.Text = _output.Text; Schedule(); };
            clear.Click += (_, _) => { _input.Clear(); _output.Clear(); Schedule(); };
            actions.Controls.Add(copy);
            actions.Controls.Add(use);
            actions.Controls.Add(clear);
            head.Controls.Add(actions, 1, 0);
        }

        box.Dock = DockStyle.Fill;
        box.Multiline = true;
        box.ScrollBars = ScrollBars.Both;
        box.WordWrap = false;
        box.AcceptsTab = true;

        side.Controls.Add(head, 0, 0);
        side.Controls.Add(box, 0, 1);
        return side;
    }

    private void BuildStatus()
    {
        var strip = new Panel { Dock = DockStyle.Bottom, Height = 40, BackColor = SoftBg, Padding = new Padding(18, 8, 18, 4) };
        _status.Dock = DockStyle.Fill;
        _status.AutoSize = false;
        _status.AutoEllipsis = true;
        _status.ForeColor = Muted;
        _status.Text = $"{Registry.All.Count} methods on the bench. Type above to search, everything updates live.";
        strip.Controls.Add(_status);
        Controls.Add(strip);
    }

    // ------------------------------------------------------------ methods

    private void SwitchMethod(CipherMethod method)
    {
        _method = method;
        _selector.SetSelectionSilently(method);
        _blurb.Text = method.Blurb;
        _learn.Text = method.Learn;
        _tips.SetToolTip(_wikiButton, method.WikiUrl);
        _wikiButton.Text = method.Category == "Defuse PHP" ? "🔗 Project on GitHub" : "🔗 Wikipedia";

        if (method.TwoWay)
        {
            _encodeRadio.Visible = true;
            _decodeRadio.Visible = true;
            _oneWayLabel.Visible = false;
            _encodeRadio.Text = method.EncodeLabel;
            _decodeRadio.Text = method.DecodeLabel;
            _encodeRadio.Checked = true;
        }
        else
        {
            _encodeRadio.Visible = false;
            _decodeRadio.Visible = false;
            _oneWayLabel.Visible = true;
            _oneWayLabel.Text = $"🔒 One-way street: {method.EncodeLabel} only. No way back.";
        }

        RebuildParams();
        _direction = CipherDirection.Encode;
        Schedule();
    }

    private void RebuildParams()
    {
        _fieldControls.Clear();
        _fieldStatus.Clear();
        _fieldSpecs.Clear();
        _paramsTable.SuspendLayout();
        _paramsTable.Controls.Clear();
        _paramsTable.RowCount = 0;
        _paramsTable.RowStyles.Clear();

        foreach (var spec in _method.Fields)
        {
            _fieldSpecs[spec.Name] = spec;
            var row = _paramsTable.RowCount;
            _paramsTable.RowStyles.Add(new RowStyle(SizeType.Absolute, spec.Kind == FieldKind.Multiline ? 96 : 40));
            _paramsTable.RowCount = row + 1;

            var label = new Label
            {
                Text = spec.Label,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                ForeColor = Ink,
            };
            _tips.SetToolTip(label, spec.Hint ?? spec.Label);

            Control input = spec.Kind switch
            {
                FieldKind.Dropdown => new ComboBox
                {
                    DropDownStyle = ComboBoxStyle.DropDownList,
                    FlatStyle = FlatStyle.Flat,
                    Dock = DockStyle.Fill,
                },
                FieldKind.Number => new NumericUpDown
                {
                    Dock = DockStyle.Fill,
                    Minimum = spec.Min ?? 0,
                    Maximum = spec.Max ?? 1_000_000,
                },
                FieldKind.Multiline => NewMonoBox(),
                _ => NewMonoBox(),
            };

            switch (input)
            {
                case TextBox tb:
                    tb.Dock = DockStyle.Fill;
                    tb.PlaceholderText = spec.Placeholder;
                    if (spec.Secret && spec.Kind != FieldKind.Multiline) tb.UseSystemPasswordChar = true;
                    tb.TextChanged += (_, _) => Schedule();
                    break;
                case ComboBox combo:
                    combo.Items.AddRange(spec.Options ?? Array.Empty<object>());
                    if (spec.Default != null) combo.SelectedItem = spec.Default;
                    else if (combo.Items.Count > 0) combo.SelectedIndex = 0;
                    combo.SelectedIndexChanged += (_, _) => Schedule();
                    break;
                case NumericUpDown num:
                    if (int.TryParse(spec.Default, out var d)) num.Value = d;
                    num.ValueChanged += (_, _) => Schedule();
                    break;
            }
            _fieldControls[spec.Name] = input;
            if (spec.Hint != null) _tips.SetToolTip(input, spec.Hint);

            var dice = new Button
            {
                Text = "🎲",
                Dock = DockStyle.Fill,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Font = new Font("Segoe UI Emoji", 11f),
                Margin = new Padding(4, 4, 4, 4),
            };
            _tips.SetToolTip(dice, "Roll something random for me");
            dice.Click += (_, _) => Roll(spec.Name);

            var status = new Label
            {
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                ForeColor = Muted,
                AutoEllipsis = true,
                Padding = new Padding(6, 0, 0, 0),
            };
            _fieldStatus[spec.Name] = status;

            _paramsTable.Controls.Add(label, 0, row);
            _paramsTable.Controls.Add(input, 1, row);
            _paramsTable.Controls.Add(spec.Generator != null ? dice : new Label(), 2, row);
            _paramsTable.Controls.Add(status, 3, row);
        }

        // A gentle nudge for methods whose required fields sit empty.
        if (_method.Fields.Any(f => f.Generator != null))
        {
            var hint = new Label
            {
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                ForeColor = Muted,
                Text = "Tip: 🎲 fills a field with a fresh random value. For RSA it mints the public and private key together.",
                Padding = new Padding(0, 2, 0, 2),
            };
            var row = _paramsTable.RowCount;
            _paramsTable.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            _paramsTable.RowCount = row + 1;
            _paramsTable.SetColumnSpan(hint, 4);
            _paramsTable.Controls.Add(hint, 0, row);
        }

        _paramsTable.ResumeLayout(true);
    }

    private void Roll(string fieldName)
    {
        try
        {
            var values = _method.Generate(fieldName, CollectFields());
            foreach (var (name, value) in values)
            {
                if (!_fieldControls.TryGetValue(name, out var control)) continue;
                switch (control)
                {
                    case TextBox tb:
                        tb.Text = value;
                        break;
                    case ComboBox cb:
                        var match = cb.Items.Cast<object>().FirstOrDefault(o => o.ToString() == value);
                        if (match != null) cb.SelectedItem = match;
                        break;
                    case NumericUpDown nd when decimal.TryParse(value, out var dv):
                        nd.Value = Math.Clamp(dv, nd.Minimum, nd.Maximum);
                        break;
                }
            }
            ValidateLive();
        }
        catch (CipherException ex)
        {
            ShowStatus(ex.Message, ErrorRed);
        }
    }

    private Dictionary<string, string> CollectFields()
    {
        var values = new Dictionary<string, string>();
        foreach (var (name, control) in _fieldControls)
        {
            values[name] = control switch
            {
                TextBox tb => tb.Text,
                ComboBox cb => cb.SelectedItem?.ToString() ?? "",
                NumericUpDown nd => nd.Value.ToString(),
                _ => "",
            };
        }
        return values;
    }

    private void DirectionChanged()
    {
        if (_encodeRadio.Checked) _direction = CipherDirection.Encode;
        else if (_decodeRadio.Checked) _direction = CipherDirection.Decode;
        else return;
        Schedule();
    }

    private void OpenWiki()
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo(_method.WikiUrl) { UseShellExecute = true };
            System.Diagnostics.Process.Start(psi);
        }
        catch (Exception)
        {
            ShowStatus($"Could not open the browser. The link: {_method.WikiUrl}", ErrorRed);
        }
    }

    private void CopyOutput()
    {
        if (_output.Text.Length == 0) return;
        try
        {
            Clipboard.SetText(_output.Text);
            var old = _status.Text;
            var oldColor = _status.ForeColor;
            ShowStatus("Copied to the clipboard.", NoteGreen);
            var uncopy = new System.Windows.Forms.Timer { Interval = 1400 };
            uncopy.Tick += (_, _) => { uncopy.Stop(); _status.Text = old; _status.ForeColor = oldColor; };
            uncopy.Start();
        }
        catch (Exception)
        {
            ShowStatus("The clipboard refused. Select the text and press Ctrl+C.", WarnOrange);
        }
    }

    // ------------------------------------------------------------ engine

    private void Schedule()
    {
        _debounce.Stop();
        _debounce.Start();
    }

    private void ValidateLive()
    {
        var validation = _method.ValidateFields(CollectFields());
        foreach (var (field, verdict) in validation.Fields)
        {
            if (_fieldStatus.TryGetValue(field, out var label))
            {
                label.Text = verdict.Certain ? (verdict.Ok ? "✔ " : "✖ ") + verdict.Message : "";
                label.ForeColor = verdict.Ok ? NoteGreen : ErrorRed;
            }
        }
        if (validation.Overall.Length > 0)
        {
            var bad = validation.Fields.Values.Any(v => v.Certain && !v.Ok);
            ShowStatus(validation.Overall, bad ? ErrorRed : NoteGreen);
        }
    }

    private void ProcessNow()
    {
        var input = _input.Text;
        try
        {
            var result = _method.Process(new CipherRequest(_direction, input, CollectFields()));
            _output.Text = result.Output;
            if (result.Warning != null) ShowStatus(result.Warning, WarnOrange);
            else if (result.Note != null) ShowStatus(result.Note, NoteGreen);
            else if (_status.ForeColor == ErrorRed || _status.ForeColor == WarnOrange || _status.ForeColor == NoteGreen)
                ResetStatus();
        }
        catch (CipherException ex)
        {
            ShowStatus(ex.Message, ErrorRed);
        }
        catch (Exception ex)
        {
            ShowStatus($"Something broke unexpectedly: {ex.Message}", ErrorRed);
        }
    }

    private void ShowStatus(string text, Color color)
    {
        _status.Text = text;
        _status.ForeColor = color;
    }

    private void ResetStatus() =>
        ShowStatus($"{Registry.All.Count} methods on the bench. Type above to search, everything updates live.", Muted);

    // ------------------------------------------------------------ factory

    private static Button NewButton(string text) => new()
    {
        Text = text,
        AutoSize = true,
        FlatStyle = FlatStyle.Flat,
        BackColor = Color.White,
        ForeColor = Accent,
        Cursor = Cursors.Hand,
        Font = new Font("Segoe UI", 9.5f),
        Padding = new Padding(8, 4, 8, 4),
    };

    private static RadioButton NewRadio(string text) => new()
    {
        Text = text,
        AutoSize = true,
        FlatStyle = FlatStyle.Flat,
        Cursor = Cursors.Hand,
    };

    private static TextBox NewMonoBox(bool readOnly = false) => new()
    {
        Font = new Font("Consolas", 10f),
        ReadOnly = readOnly,
        BackColor = readOnly ? SoftBg : Color.White,
        BorderStyle = BorderStyle.FixedSingle,
    };
}
