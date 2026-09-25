using Mtkey.Core;

namespace Mtkey;

/// <summary>A classic Win32-style workbench: menu bar, one toolbar row,
/// group boxes for parameters and text, and a status bar at the bottom.
/// Everything uses system colors, system fonts and stock themed controls,
/// dense like a Windows 7 era utility.</summary>
internal sealed class MainForm : Form
{
    private static readonly Color NoteGreen = Color.FromArgb(0, 128, 0);
    private static readonly Color WarnOrange = Color.FromArgb(196, 88, 0);
    private static readonly Color ErrorRed = Color.FromArgb(180, 0, 0);

    private const int LabelWidth = 116;
    private const int DiceWidth = 30;
    private const int GlyphWidth = 16;

    private readonly SearchDropDown _selector = new();
    private readonly Button _wikiButton = NewButton("Wikipedia");
    private readonly Button _helpButton = NewButton("?");
    private readonly RadioButton _encodeRadio = new() { Text = "Encode", AutoSize = true };
    private readonly RadioButton _decodeRadio = new() { Text = "Decode", AutoSize = true };
    private readonly Label _oneWayLabel = new()
    {
        Text = "One-way: hash only",
        AutoSize = true,
        ForeColor = SystemColors.GrayText,
    };
    private readonly Label _blurb = new()
    {
        Dock = DockStyle.Fill,
        AutoEllipsis = true,
        ForeColor = SystemColors.GrayText,
    };

    private readonly GroupBox _paramsGroup = NewGroup("Parameters");
    private readonly GroupBox _inputGroup = NewGroup("Input");
    private readonly GroupBox _outputGroup = NewGroup("Output");

    private readonly TextBox _input = NewMonoBox();
    private readonly TextBox _output = NewMonoBox(readOnly: true);
    private readonly Button _copyButton = NewButton("Copy");
    private readonly Button _useButton = NewButton("Use as Input");
    private readonly Button _clearButton = NewButton("Clear");

    private readonly StatusStrip _statusStrip = new();
    private readonly ToolStripStatusLabel _statusLabel = new() { Spring = true };
    private readonly ToolStripStatusLabel _countLabel = new();

    private readonly System.Windows.Forms.Timer _debounce = new() { Interval = 220 };
    private readonly ToolTip _tips = new();

    private CipherMethod _method = Registry.All[0];
    private CipherDirection _direction = CipherDirection.Encode;
    private readonly Dictionary<string, Control> _fieldControls = new();
    private readonly Dictionary<string, Label> _fieldGlyphs = new();

    /// <param name="demoInput">Pre-fills the input box, used by --demo.</param>
    public MainForm(string? demoInput = null)
    {
        Text = "MTKey";
        StartPosition = FormStartPosition.CenterScreen;
        Font = SystemFonts.MessageBoxFont;
        BackColor = SystemColors.Control;
        ForeColor = SystemColors.ControlText;
        MinimumSize = new Size(760, 540);
        MaximumSize = new Size(1200, 900);
        ClientSize = new Size(880, 600);

        BuildMenu();
        BuildToolbar();
        BuildBlurbRow();
        BuildParamsGroup();
        BuildIoArea();
        BuildStatusBar();

        _selector.MethodPicked += m => SwitchMethod(m);
        _wikiButton.Click += (_, _) => OpenWiki();
        _helpButton.Click += (_, _) => ShowMethodHelp();
        _tips.SetToolTip(_helpButton, "What is this method? (F1)");
        _blurb.Click += (_, _) => ShowMethodHelp();
        _encodeRadio.CheckedChanged += (_, _) => DirectionChanged();
        _decodeRadio.CheckedChanged += (_, _) => DirectionChanged();
        _copyButton.Click += (_, _) => CopyOutput();
        _useButton.Click += (_, _) => { _input.Text = _output.Text; Schedule(); };
        _clearButton.Click += (_, _) => { _input.Clear(); _output.Clear(); Schedule(); };

        _debounce.Tick += (_, _) => { _debounce.Stop(); ValidateLive(); ProcessNow(); };

        SwitchMethod(Registry.All[0]);

        if (demoInput != null)
        {
            _input.Text = demoInput;
            Schedule();
        }
    }

    // ------------------------------------------------------------ layout

    private void BuildMenu()
    {
        var menu = new MenuStrip();
        var file = new ToolStripMenuItem("&File");
        file.DropDownItems.Add(new ToolStripMenuItem("E&xit", null, (_, _) => Close()));
        var help = new ToolStripMenuItem("&Help");
        help.DropDownItems.Add(new ToolStripMenuItem("&About this method", null,
            (_, _) => ShowMethodHelp(), Keys.F1));
        help.DropDownItems.Add(new ToolStripMenuItem("Open &Wikipedia page", null,
            (_, _) => OpenWiki()));
        help.DropDownItems.Add(new ToolStripMenuItem("&Run self-test", null,
            (_, _) => RunSelfTestFromMenu()));
        help.DropDownItems.Add(new ToolStripSeparator());
        help.DropDownItems.Add(new ToolStripMenuItem("&About MTKey...", null,
            (_, _) => MessageBox.Show(this,
                "MTKey 1.0.2\nA cipher workbench: encode, decode, hash, sign, and learn.\n" +
                $"{Registry.All.Count} methods. MIT licensed.\nhttps://github.com/eru123/mtkey",
                "About MTKey", MessageBoxButtons.OK, MessageBoxIcon.Information)));
        menu.Items.Add(file);
        menu.Items.Add(help);
        MainMenuStrip = menu;
        Controls.Add(menu);
    }

    private void BuildToolbar()
    {
        var bar = new Panel { Dock = DockStyle.Top, Height = 28, Padding = new Padding(6, 2, 6, 2) };
        bar.Controls.Add(_selector);
        bar.Controls.Add(_wikiButton);
        bar.Controls.Add(_helpButton);
        bar.Controls.Add(_encodeRadio);
        bar.Controls.Add(_decodeRadio);
        bar.Controls.Add(_oneWayLabel);

        // absolute placement on every resize; no anchors fighting manual math
        void Place()
        {
            var w = bar.ClientSize.Width;
            _selector.Bounds = new Rectangle(0, 2, Math.Max(120, w - 430), 23);
            _wikiButton.Location = new Point(w - 410, 2);
            _helpButton.Location = new Point(w - 326, 2);
            _encodeRadio.Location = new Point(w - 268, 4);
            _decodeRadio.Location = new Point(w - 196, 4);
            _oneWayLabel.Location = new Point(w - 292, 7);
        }
        bar.Resize += (_, _) => Place();
        Controls.Add(bar);
    }

    private void BuildBlurbRow()
    {
        var bar = new Panel { Dock = DockStyle.Top, Height = 18, Padding = new Padding(8, 1, 8, 1) };
        bar.Controls.Add(_blurb);
        _tips.SetToolTip(_blurb, "Click for the full explanation");
        Controls.Add(bar);
    }

    private void BuildParamsGroup()
    {
        _paramsGroup.Dock = DockStyle.Top;
        _paramsGroup.AutoSize = true;
        _paramsGroup.Padding = new Padding(8, 4, 8, 4);
        _paramsGroup.Margin = new Padding(6, 2, 6, 2);
        Controls.Add(_paramsGroup);
    }

    private void BuildIoArea()
    {
        var grid = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            Padding = new Padding(6, 2, 6, 4),
            Margin = Padding.Empty,
        };
        grid.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
        grid.RowStyles.Add(new RowStyle(SizeType.Percent, 50));

        _inputGroup.Dock = DockStyle.Fill;
        _inputGroup.Padding = new Padding(8, 2, 8, 6);
        _input.Dock = DockStyle.Fill;
        _input.Multiline = true;
        _input.ScrollBars = ScrollBars.Both;
        _input.WordWrap = false;
        _input.AcceptsTab = true;
        _inputGroup.Controls.Add(_input);

        _outputGroup.Dock = DockStyle.Fill;
        _outputGroup.Padding = new Padding(8, 2, 8, 6);
        var actions = new Panel { Dock = DockStyle.Top, Height = 25, Margin = new Padding(0, 0, 0, 2) };
        var buttons = new[] { _clearButton, _useButton, _copyButton };
        actions.Controls.AddRange(buttons);
        void Place()
        {
            var x = actions.ClientSize.Width;
            foreach (var b in buttons)
            {
                x -= b.Width + 4;
                b.Location = new Point(x, 1);
            }
        }
        actions.Resize += (_, _) => Place();
        _outputGroup.Controls.Add(actions);
        _output.Dock = DockStyle.Fill;
        _output.Multiline = true;
        _output.ScrollBars = ScrollBars.Both;
        _output.WordWrap = false;
        _outputGroup.Controls.Add(_output);
        // dock order is fill-then-top here, so re-dock to keep buttons above text
        _output.BringToFront();

        grid.Controls.Add(_inputGroup, 0, 0);
        grid.Controls.Add(_outputGroup, 0, 1);
        Controls.Add(grid);
        // dock layout walks children from the end of the collection inward,
        // so the fill area must sit at index 0 to claim only the leftover
        // space below every top-docked row
        Controls.SetChildIndex(grid, 0);
    }

    private void BuildStatusBar()
    {
        _statusStrip.Items.Add(_statusLabel);
        _statusStrip.Items.Add(_countLabel);
        _countLabel.Text = $"{Registry.All.Count} methods";
        _countLabel.BorderSides = ToolStripStatusLabelBorderSides.Left;
        _countLabel.BorderStyle = Border3DStyle.Etched;
        _statusStrip.SizingGrip = true;
        Controls.Add(_statusStrip);
        _statusLabel.Text = "Ready.";
    }

    // ------------------------------------------------------------ params

    private void RebuildParams()
    {
        _fieldControls.Clear();
        _fieldGlyphs.Clear();
        _paramsGroup.SuspendLayout();

        var oldRows = _paramsGroup.Controls.Cast<Control>().ToList();
        _paramsGroup.Controls.Clear();
        foreach (var row in oldRows) row.Dispose();

        var rows = new List<Control>();
        foreach (var spec in _method.Fields)
            rows.Add(BuildFieldRow(spec));

        if (_method.Fields.Any(f => f.Generator != null))
        {
            rows.Add(new Label
            {
                Dock = DockStyle.Top,
                Height = 16,
                Text = "Tip: the dice button rolls a fresh random value; on RSA it mints the key pair.",
                ForeColor = SystemColors.GrayText,
            });
        }

        foreach (var row in ((IEnumerable<Control>)rows).Reverse())
            _paramsGroup.Controls.Add(row);

        _paramsGroup.Visible = _method.Fields.Count > 0;
        _paramsGroup.ResumeLayout(true);
    }

    private Control BuildFieldRow(FieldSpec spec)
    {
        var multiline = spec.Kind == FieldKind.Multiline;
        var row = new Panel { Dock = DockStyle.Top, Height = multiline ? 78 : 26 };

        var label = new Label
        {
            Text = spec.Label,
            AutoSize = false,
            Bounds = new Rectangle(0, multiline ? 2 : 4, LabelWidth, 18),
            TextAlign = ContentAlignment.MiddleLeft,
        };
        _tips.SetToolTip(label, spec.Hint ?? spec.Label);
        row.Controls.Add(label);

        Control input = spec.Kind switch
        {
            FieldKind.Dropdown => new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList },
            FieldKind.Number => new NumericUpDown
            {
                Minimum = spec.Min ?? 0,
                Maximum = spec.Max ?? 1_000_000,
            },
            FieldKind.Multiline => NewMonoBox(),
            _ => NewMonoBox(),
        };

        var left = LabelWidth + 2;
        var reserve = (spec.Generator != null ? DiceWidth : 0) + GlyphWidth;
        input.Bounds = new Rectangle(left, multiline ? 0 : 1,
            Math.Max(60, row.ClientSize.Width - left - reserve),
            multiline ? 76 : 23);
        switch (input)
        {
            case TextBox tb:
                tb.PlaceholderText = spec.Placeholder;
                if (spec.Secret && !multiline) tb.UseSystemPasswordChar = true;
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

        Button? dice = null;
        if (spec.Generator != null)
        {
            dice = NewButton("🎲");
            dice.AutoSize = false;
            dice.Bounds = new Rectangle(row.ClientSize.Width - DiceWidth - GlyphWidth, 1, DiceWidth - 4, 23);
            _tips.SetToolTip(dice, "Roll a random value");
            dice.Click += (_, _) => Roll(spec.Name);
            row.Controls.Add(dice);
        }

        var glyph = new Label
        {
            Bounds = new Rectangle(row.ClientSize.Width - GlyphWidth, multiline ? 2 : 6, GlyphWidth, 16),
            TextAlign = ContentAlignment.MiddleLeft,
            Text = "",
        };
        _fieldGlyphs[spec.Name] = glyph;
        row.Controls.Add(glyph);

        row.Resize += (_, _) =>
        {
            input.Width = Math.Max(60, row.ClientSize.Width - left - reserve);
            if (dice != null)
                dice.Location = new Point(row.ClientSize.Width - DiceWidth - GlyphWidth, 1);
            glyph.Location = new Point(row.ClientSize.Width - GlyphWidth, multiline ? 2 : 6);
        };

        return row;
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
            Schedule();
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

    // ------------------------------------------------------------ engine

    private void SwitchMethod(CipherMethod method)
    {
        _method = method;
        _selector.SetSelectionSilently(method);
        _blurb.Text = method.Blurb;
        _tips.SetToolTip(_blurb, method.Blurb + "\n\nClick for the full explanation.");
        _tips.SetToolTip(_wikiButton, method.WikiUrl);
        _wikiButton.Text = method.Category == "Defuse PHP" ? "GitHub" : "Wikipedia";

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
            _oneWayLabel.Text = $"One-way: {method.EncodeLabel} only";
        }

        RebuildParams();
        _direction = CipherDirection.Encode;
        Schedule();
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
            ShowStatus($"Could not open the browser: {_method.WikiUrl}", ErrorRed);
        }
    }

    private void ShowMethodHelp()
    {
        var wiki = _method.Category == "Defuse PHP" ? "Project" : "Wikipedia";
        MessageBox.Show(this,
            $"{_method.Name} ({_method.Category})\n\n{_method.Blurb}\n\n{_method.Learn}\n\n" +
            $"{wiki}: {_method.WikiUrl}",
            _method.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void RunSelfTestFromMenu()
    {
        ShowStatus("Running self-test...", SystemColors.ControlText);
        Refresh();
        var results = SelfTest.Run();
        var failed = results.Count(c => !c.Pass);
        if (failed == 0)
            MessageBox.Show(this, $"{results.Count}/{results.Count} checks passed.",
                "Self-test", MessageBoxButtons.OK, MessageBoxIcon.Information);
        else
            MessageBox.Show(this,
                string.Join("\n", results.Where(c => !c.Pass).Select(c => $"FAIL {c.Name}: {c.Detail}")),
                $"Self-test: {failed} failures", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        ResetStatus();
    }

    private void CopyOutput()
    {
        if (_output.Text.Length == 0) return;
        try
        {
            Clipboard.SetText(_output.Text);
            ShowStatus("Copied to clipboard.", NoteGreen);
        }
        catch (Exception)
        {
            ShowStatus("Clipboard refused; select the text and press Ctrl+C.", WarnOrange);
        }
    }

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
            if (!_fieldGlyphs.TryGetValue(field, out var glyph)) continue;
            glyph.Text = verdict.Certain ? (verdict.Ok ? "✔" : "✖") : "";
            glyph.ForeColor = verdict.Ok ? NoteGreen : ErrorRed;
            if (verdict.Certain)
                _tips.SetToolTip(glyph, verdict.Message);
        }
        if (validation.Overall.Length > 0)
        {
            var bad = validation.Fields.Values.Any(v => v.Certain && !v.Ok);
            ShowStatus(validation.Overall, bad ? ErrorRed : NoteGreen);
        }
    }

    private void ProcessNow()
    {
        try
        {
            var result = _method.Process(new CipherRequest(_direction, _input.Text, CollectFields()));
            _output.Text = result.Output;
            if (result.Warning != null) ShowStatus(result.Warning, WarnOrange);
            else if (result.Note != null) ShowStatus(result.Note, NoteGreen);
            else if (_statusLabel.ForeColor != SystemColors.ControlText)
                ResetStatus();
        }
        catch (CipherException ex)
        {
            ShowStatus(ex.Message, ErrorRed);
        }
        catch (Exception ex)
        {
            ShowStatus($"Unexpected: {ex.Message}", ErrorRed);
        }
    }

    private void ShowStatus(string text, Color color)
    {
        _statusLabel.Text = text;
        _statusLabel.ForeColor = color;
    }

    private void ResetStatus() => ShowStatus("Ready.", SystemColors.ControlText);

    // -------------------------------------------------- checks and probes

    /// <summary>Used by --render to photograph a specific method.</summary>
    internal void SelectMethod(string id)
    {
        var method = Registry.Find(id);
        if (method != null) SwitchMethod(method);
    }

    /// <summary>Fills parameter fields before the window is shown; used by
    /// --demo and --render so screenshots show a working session.</summary>
    internal void ApplyDemoFields(IReadOnlyDictionary<string, string> fields)
    {
        foreach (var (name, value) in fields)
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
        Schedule();
    }

    /// <summary>Walks the visible layout and reports anything that overlaps,
    /// falls outside the window or collapses to nothing. Backs the
    /// --layoutcheck mode so broken rows never ship again.</summary>
    internal List<string> LayoutDefects()
    {
        var defects = new List<string>();

        foreach (Control row in _paramsGroup.Controls)
        {
            var boxes = row.Controls.Cast<Control>().Select(c => c.Bounds).ToList();
            for (var i = 0; i < boxes.Count; i++)
                for (var j = i + 1; j < boxes.Count; j++)
                    if (boxes[i].IntersectsWith(boxes[j]))
                        defects.Add($"{_method.Id}: parameter row controls overlap");
            foreach (Control child in row.Controls)
                if (child.Width <= 1)
                    defects.Add($"{_method.Id}: a parameter row control collapsed to width {child.Width}");
        }

        if (_input.Height < 36) defects.Add($"{_method.Id}: input box crushed to {_input.Height}px");
        if (_output.Height < 36) defects.Add($"{_method.Id}: output box crushed to {_output.Height}px");

        // the action buttons and the output text share one group box
        foreach (Control child in _outputGroup.Controls)
            foreach (Control other in _outputGroup.Controls)
                if (!ReferenceEquals(child, other) &&
                    child.Bounds.IntersectsWith(other.Bounds) &&
                    child is TextBox or Button or Panel)
                    defects.Add($"{_method.Id}: output group children overlap ({child.GetType().Name} vs {other.GetType().Name})");

        // group boxes must stack, never intersect (bounds live in different
        // parents, so compare in screen space)
        Rectangle ScreenBounds(Control c) => c.Parent!.RectangleToScreen(c.Bounds);
        var groups = new[] { (Control)_paramsGroup, _inputGroup, _outputGroup };
        for (var i = 0; i < groups.Length; i++)
            for (var j = i + 1; j < groups.Length; j++)
                if (groups[i].Visible && groups[j].Visible &&
                    ScreenBounds(groups[i]).IntersectsWith(Rectangle.Inflate(ScreenBounds(groups[j]), -2, -2)))
                    defects.Add($"{_method.Id}: {groups[i].Text} and {groups[j].Text} group boxes intersect " +
                                $"[{ScreenBounds(groups[i])}] vs [{ScreenBounds(groups[j])}]");

        foreach (var control in new Control[] { _selector, _input, _output, _statusStrip })
        {
            var screen = control.Parent!.RectangleToScreen(control.Bounds);
            var form = Rectangle.Inflate(RectangleToScreen(ClientRectangle), 1, 1);
            if (!form.Contains(screen.Location) || !form.Contains(screen.Right, screen.Bottom))
                defects.Add($"{_method.Id}: {control.GetType().Name} falls outside the window");
        }

        return defects;
    }

    internal void RunLayoutPass()
    {
        PerformLayout();
        Application.DoEvents();
    }

    // ------------------------------------------------------------ factory

    private static Button NewButton(string text) => new()
    {
        Text = text,
        AutoSize = true,
        Padding = new Padding(6, 0, 6, 0),
        Margin = new Padding(1),
    };

    private static GroupBox NewGroup(string caption) => new()
    {
        Text = caption,
        AutoSize = false,
    };

    private static TextBox NewMonoBox(bool readOnly = false) => new()
    {
        Font = new Font("Consolas", 9f),
        ReadOnly = readOnly,
    };
}
