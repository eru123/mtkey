using Mtkey.Core;

namespace Mtkey;

/// <summary>The whole workbench: pick a cipher, fill its parameters (roll the
/// dice for anything random), and watch the output update live. The layout is
/// deliberately plain: fixed-height rows docked top down, no table panels
/// juggling row styles, inputs anchored left and right.</summary>
internal sealed class MainForm : Form
{
    private static readonly Color Ink = Color.FromArgb(31, 33, 40);
    private static readonly Color Muted = Color.FromArgb(96, 100, 110);
    private static readonly Color Accent = Color.FromArgb(79, 70, 229);
    private static readonly Color NoteGreen = Color.FromArgb(22, 101, 52);
    private static readonly Color WarnOrange = Color.FromArgb(154, 52, 18);
    private static readonly Color ErrorRed = Color.FromArgb(185, 28, 28);
    private static readonly Color SoftBg = Color.FromArgb(250, 250, 252);
    private static readonly Color Line = Color.FromArgb(226, 228, 234);

    private const int LabelWidth = 128;
    private const int DiceWidth = 34;
    private const int GlyphWidth = 22;

    private readonly SearchDropDown _selector = new() { Dock = DockStyle.Fill };
    private readonly Button _wikiButton = NewButton("🔗 Wikipedia");
    private readonly Label _blurb = new();
    private readonly Label _learn = new();
    private readonly RadioButton _encodeRadio = NewRadio("Encode");
    private readonly RadioButton _decodeRadio = NewRadio("Decode");
    private readonly Label _oneWayLabel = new();
    private readonly Panel _paramsHost = new();
    private readonly TextBox _input = NewMonoBox();
    private readonly TextBox _output = NewMonoBox(readOnly: true);
    private readonly Label _status = new();
    private readonly System.Windows.Forms.Timer _debounce = new() { Interval = 220 };
    private readonly ToolTip _tips = new();

    private CipherMethod _method = Registry.All[0];
    private CipherDirection _direction = CipherDirection.Encode;
    private readonly Dictionary<string, Control> _fieldControls = new();
    private readonly Dictionary<string, Label> _fieldGlyphs = new();
    private readonly Dictionary<string, FieldSpec> _fieldSpecs = new();
    private string _plainStatus = "";

    /// <param name="demoInput">Pre-fills the input box, used by --demo.</param>
    public MainForm(string? demoInput = null)
    {
        Text = "MTKey";
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9f);
        BackColor = Color.White;
        ForeColor = Ink;
        MinimumSize = new Size(780, 580);
        MaximumSize = new Size(1100, 860);
        ClientSize = new Size(940, 660);

        BuildHeader();
        BuildSelectorRow();
        BuildInfoPanel();
        BuildDirectionRow();
        BuildParamsHost();
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
        var panel = new Panel { Dock = DockStyle.Top, Height = 42, Padding = new Padding(14, 8, 14, 4) };
        var title = new Label
        {
            Text = "MTKey",
            Font = new Font("Segoe UI Semibold", 13.5f),
            ForeColor = Color.FromArgb(49, 46, 129),
            AutoSize = true,
            Location = new Point(14, 8),
        };
        var subtitle = new Label
        {
            Text = "a crypto playground: encode, decode, hash, sign, and learn how each one works",
            Font = new Font("Segoe UI", 8.75f),
            ForeColor = Muted,
            AutoSize = true,
            Location = new Point(92, 18),
        };
        panel.Controls.Add(title);
        panel.Controls.Add(subtitle);
        Controls.Add(panel);
    }

    private void BuildSelectorRow()
    {
        var panel = new Panel { Dock = DockStyle.Top, Height = 40, Padding = new Padding(14, 4, 14, 4) };
        var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, Margin = Padding.Empty };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));
        _selector.Margin = new Padding(0, 2, 6, 2);
        grid.Controls.Add(_selector, 0, 0);
        _wikiButton.AutoSize = false;
        _wikiButton.Dock = DockStyle.Fill;
        _wikiButton.Margin = new Padding(0, 2, 0, 2);
        _wikiButton.TextAlign = ContentAlignment.MiddleCenter;
        _wikiButton.Font = new Font("Segoe UI Emoji", 9f);
        grid.Controls.Add(_wikiButton, 1, 0);
        panel.Controls.Add(grid);
        Controls.Add(panel);
    }

    private void BuildInfoPanel()
    {
        var panel = new Panel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(14, 3, 14, 5), BackColor = SoftBg };
        _blurb.Dock = DockStyle.Top;
        _blurb.Font = new Font("Segoe UI Semibold", 9.5f);
        _blurb.ForeColor = Ink;
        _blurb.AutoSize = true;
        _blurb.Padding = new Padding(0, 1, 0, 1);

        _learn.Dock = DockStyle.Top;
        _learn.Font = new Font("Segoe UI", 8.75f);
        _learn.ForeColor = Muted;
        _learn.AutoSize = true;
        _learn.MaximumSize = new Size(900, 0);
        _learn.Padding = new Padding(0, 1, 0, 3);

        panel.Controls.Add(_learn);
        panel.Controls.Add(_blurb);
        Controls.Add(panel);
    }

    private void BuildDirectionRow()
    {
        var panel = new Panel { Dock = DockStyle.Top, Height = 30, Padding = new Padding(14, 2, 14, 0) };
        _encodeRadio.CheckedChanged += (_, _) => DirectionChanged();
        _decodeRadio.CheckedChanged += (_, _) => DirectionChanged();
        _oneWayLabel.AutoSize = true;
        _oneWayLabel.ForeColor = Muted;
        _oneWayLabel.Location = new Point(6, 6);
        _encodeRadio.Location = new Point(6, 3);
        _decodeRadio.Location = new Point(112, 3);
        panel.Controls.Add(_encodeRadio);
        panel.Controls.Add(_decodeRadio);
        panel.Controls.Add(_oneWayLabel);
        Controls.Add(panel);
    }

    private void BuildParamsHost()
    {
        _paramsHost.Dock = DockStyle.Top;
        _paramsHost.AutoSize = true;
        _paramsHost.Padding = new Padding(14, 2, 14, 2);
        Controls.Add(_paramsHost);
    }

    private void BuildIoArea()
    {
        var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Padding = new Padding(14, 3, 14, 4), Margin = Padding.Empty };
        grid.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
        grid.RowStyles.Add(new RowStyle(SizeType.Percent, 50));

        grid.Controls.Add(BuildOneSide("Input", _input, buttons: false), 0, 0);
        grid.Controls.Add(BuildOneSide("Output", _output, buttons: true), 0, 1);
        Controls.Add(grid);
    }

    private Control BuildOneSide(string caption, TextBox box, bool buttons)
    {
        var side = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = new Padding(0, 3, 0, 3) };
        side.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        side.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var head = new Panel { Dock = DockStyle.Top, Height = 24, Margin = new Padding(0, 0, 0, 3) };
        var label = new Label
        {
            Text = caption,
            Font = new Font("Segoe UI Semibold", 9.5f),
            ForeColor = Ink,
            AutoSize = true,
            Location = new Point(0, 2),
        };
        head.Controls.Add(label);

        if (buttons)
        {
            var copy = NewButton("📋 Copy");
            var use = NewButton("↩ Use as input");
            var clear = NewButton("🧹 Clear");
            copy.Click += (_, _) => CopyOutput();
            use.Click += (_, _) => { _input.Text = _output.Text; Schedule(); };
            clear.Click += (_, _) => { _input.Clear(); _output.Clear(); Schedule(); };
            // right-aligned right to left: first control ends up rightmost
            head.Controls.Add(copy);
            head.Controls.Add(use);
            head.Controls.Add(clear);
            PositionButtonRow(head, copy, use, clear);
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

    private static void PositionButtonRow(Panel head, params Button[] buttons)
    {
        // layout right to left with a fixed 4px gutter, plus a one-shot
        // relayout when the window width changes
        void Place()
        {
            var x = head.Width;
            foreach (var b in buttons)
            {
                x -= b.Width + 4;
                b.Location = new Point(x, 0);
            }
        }
        Place();
        head.Resize += (_, _) => Place();
    }

    private void BuildStatus()
    {
        var strip = new Panel { Dock = DockStyle.Bottom, Height = 30, BackColor = SoftBg, Padding = new Padding(14, 6, 14, 2) };
        _status.Dock = DockStyle.Fill;
        _status.AutoEllipsis = true;
        _status.ForeColor = Muted;
        _status.Text = "";
        strip.Controls.Add(_status);
        Controls.Add(strip);
        _plainStatus = $"{Registry.All.Count} methods on the bench. Type above to search, everything updates live.";
        ResetStatus();
    }

    // ------------------------------------------------------------ params

    private void RebuildParams()
    {
        _fieldControls.Clear();
        _fieldGlyphs.Clear();
        _fieldSpecs.Clear();
        _paramsHost.SuspendLayout();

        var oldRows = _paramsHost.Controls.Cast<Control>().ToList();
        _paramsHost.Controls.Clear();
        foreach (var row in oldRows) row.Dispose();

        // Rows are docked Top, so add them in reverse to keep reading order.
        var rows = new List<Control>();
        foreach (var spec in _method.Fields)
            rows.Add(BuildFieldRow(spec));

        if (_method.Fields.Any(f => f.Generator != null))
        {
            rows.Add(new Panel
            {
                Dock = DockStyle.Top,
                Height = 24,
                Controls =
                {
                    new Label
                    {
                        Text = "Tip: 🎲 rolls a fresh random value. On RSA it mints the public and private key together.",
                        Dock = DockStyle.Fill,
                        TextAlign = ContentAlignment.MiddleLeft,
                        ForeColor = Muted,
                        Font = new Font("Segoe UI", 8.25f),
                    },
                },
            });
        }

        foreach (var row in ((IEnumerable<Control>)rows).Reverse())
            _paramsHost.Controls.Add(row);

        _paramsHost.ResumeLayout(true);
    }

    private Control BuildFieldRow(FieldSpec spec)
    {
        _fieldSpecs[spec.Name] = spec;
        var multiline = spec.Kind == FieldKind.Multiline;
        var row = new Panel { Dock = DockStyle.Top, Height = multiline ? 84 : 32, Padding = new Padding(0, 2, 0, 2) };

        var label = new Label
        {
            Text = spec.Label,
            Font = new Font("Segoe UI", 9f),
            ForeColor = Ink,
            AutoSize = false,
            Bounds = new Rectangle(0, multiline ? 3 : 6, LabelWidth, 20),
            TextAlign = ContentAlignment.MiddleLeft,
        };
        _tips.SetToolTip(label, spec.Hint ?? spec.Label);
        row.Controls.Add(label);

        Control input = spec.Kind switch
        {
            FieldKind.Dropdown => new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Font = new Font("Segoe UI", 9f),
            },
            FieldKind.Number => new NumericUpDown
            {
                Font = new Font("Segoe UI", 9f),
                Minimum = spec.Min ?? 0,
                Maximum = spec.Max ?? 1_000_000,
            },
            FieldKind.Multiline => NewMonoBox(),
            _ => NewMonoBox(),
        };

        var left = LabelWidth + 4;
        var widthReserve = (spec.Generator != null ? DiceWidth : 0) + GlyphWidth + 4;
        input.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        input.Bounds = new Rectangle(left, multiline ? 2 : 4,
            Math.Max(60, row.ClientSize.Width - left - widthReserve - row.Padding.Horizontal),
            multiline ? 80 : 24);
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
            dice = new Button
            {
                Text = "🎲",
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Font = new Font("Segoe UI Emoji", 9.5f),
                Anchor = AnchorStyles.Right,
                Bounds = new Rectangle(row.ClientSize.Width - DiceWidth - GlyphWidth - 4, multiline ? 0 : 2, DiceWidth - 6, 26),
                Padding = new Padding(0),
                Margin = Padding.Empty,
            };
            _tips.SetToolTip(dice, "Roll something random for me");
            dice.Click += (_, _) => Roll(spec.Name);
            row.Controls.Add(dice);
        }

        var glyph = new Label
        {
            Font = new Font("Segoe UI", 9.5f),
            ForeColor = NoteGreen,
            Anchor = AnchorStyles.Right,
            Bounds = new Rectangle(row.ClientSize.Width - GlyphWidth, multiline ? 3 : 7, GlyphWidth, 18),
            TextAlign = ContentAlignment.MiddleLeft,
            Text = "",
        };
        _fieldGlyphs[spec.Name] = glyph;
        row.Controls.Add(glyph);

        // keep the input stretching and the right-side pieces pinned on resize
        row.Resize += (_, _) =>
        {
            input.Width = Math.Max(60, row.ClientSize.Width - left - widthReserve - row.Padding.Horizontal);
            if (dice != null)
                dice.Bounds = new Rectangle(row.ClientSize.Width - DiceWidth - GlyphWidth - 4, multiline ? 0 : 2, DiceWidth - 6, 26);
            glyph.Bounds = new Rectangle(row.ClientSize.Width - GlyphWidth, multiline ? 3 : 7, GlyphWidth, 18);
        };

        return row;
    }

    // The dice button created in BuildFieldRow is captured by that row's
    // resize handler, so the anchored pieces stay pinned when the window
    // changes size.

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
        _learn.Text = method.Learn;
        _tips.SetToolTip(_wikiButton, method.WikiUrl);
        _wikiButton.Text = method.Category == "Defuse PHP" ? "🔗 Project" : "🔗 Wikipedia";

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

    /// <summary>Used by --render to photograph a specific method.</summary>
    internal void SelectMethod(string id)
    {
        var method = Registry.Find(id);
        if (method != null) SwitchMethod(method);
    }

    /// <summary>Walks the visible layout and reports anything that overlaps,
    /// sits outside the window or collapses to nothing. Backs the
    /// --layoutcheck mode so broken rows never ship again.</summary>
    internal List<string> LayoutDefects()
    {
        var defects = new List<string>();
        var client = ClientRectangle;

        foreach (Control row in _paramsHost.Controls)
        {
            var boxes = new List<Rectangle>();
            foreach (Control child in row.Controls)
                boxes.Add(child.Bounds);
            for (var i = 0; i < boxes.Count; i++)
                for (var j = i + 1; j < boxes.Count; j++)
                    if (boxes[i].IntersectsWith(boxes[j]))
                        defects.Add($"{_method.Id}: '{row.Controls[i].Name ?? row.Controls[i].Text}' overlaps " +
                                    $"'{row.Controls[j].Name ?? row.Controls[j].Text}'");
            foreach (Control child in row.Controls)
            {
                if (child.Width <= 1)
                    defects.Add($"{_method.Id}: a control in a parameter row collapsed to width {child.Width}");
            }
        }

        if (_input.Height < 36) defects.Add($"{_method.Id}: input box crushed to {_input.Height}px");
        if (_output.Height < 36) defects.Add($"{_method.Id}: output box crushed to {_output.Height}px");

        foreach (var control in new Control[] { _selector, _input, _output, _status })
        {
            var screen = control.Parent!.RectangleToScreen(control.Bounds);
            var form = RectangleToScreen(client);
            if (!form.Contains(screen.Location) || !form.Contains(screen.Right, screen.Bottom))
                defects.Add($"{_method.Id}: {control.GetType().Name} falls outside the window");
        }

        return defects;
    }

    internal void RunLayoutPass()
    {
        // forces a full layout pass so measured sizes are final
        PerformLayout();
        Application.DoEvents();
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

    private void ResetStatus() => ShowStatus(_plainStatus, Muted);

    // ------------------------------------------------------------ factory

    private static Button NewButton(string text) => new()
    {
        Text = text,
        AutoSize = true,
        FlatStyle = FlatStyle.Flat,
        BackColor = Color.White,
        ForeColor = Accent,
        Cursor = Cursors.Hand,
        Font = new Font("Segoe UI Emoji", 8.75f),
        Padding = new Padding(6, 2, 6, 2),
        Margin = Padding.Empty,
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
        Font = new Font("Consolas", 9.5f),
        ReadOnly = readOnly,
        BackColor = readOnly ? SoftBg : Color.White,
        BorderStyle = BorderStyle.FixedSingle,
    };
}
