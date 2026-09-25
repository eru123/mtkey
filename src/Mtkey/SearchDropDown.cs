using Mtkey.Core;

namespace Mtkey;

/// <summary>A classic combo-style text box that filters a dropdown list as you
/// type: type "b64", "defuse" or "sha2" and the list shrinks to the matches.
/// Arrow keys walk the list, Enter or click picks, Esc closes.</summary>
internal sealed class SearchDropDown : Control
{
    private readonly TextBox _box = new();
    private readonly Button _chevron = new();
    private readonly ToolStripDropDown _popup = new() { AutoClose = true, Padding = Padding.Empty };
    private readonly ListBox _list = new()
    {
        BorderStyle = BorderStyle.None,
        IntegralHeight = false,
        ItemHeight = 20,
        Font = SystemFonts.MessageBoxFont,
    };

    private IReadOnlyList<CipherMethod> _items = Array.Empty<CipherMethod>();
    private IReadOnlyList<CipherMethod> _filtered = Array.Empty<CipherMethod>();
    private bool _suppress;

    public event Action<CipherMethod>? MethodPicked;

    public SearchDropDown()
    {
        Height = 23;

        _box.Dock = DockStyle.Fill;
        _box.Font = SystemFonts.MessageBoxFont;
        _box.PlaceholderText = "Search a cipher: base64, defuse, sha2, jwt...";

        _chevron.Dock = DockStyle.Right;
        _chevron.Width = 20;
        _chevron.Text = "▾";
        _chevron.Cursor = Cursors.Hand;

        Controls.Add(_box);
        Controls.Add(_chevron);

        _box.TextChanged += (_, _) => { if (!_suppress) Refilter(show: true); };
        _box.KeyDown += OnBoxKeyDown;
        _box.Click += (_, _) => { if (_list.Items.Count > 0) ShowPopup(); };
        _chevron.Click += (_, _) => { Refilter(string.Empty, show: true); _box.Focus(); };

        var host = new ToolStripControlHost(_list) { AutoSize = false, Margin = Padding.Empty };
        _popup.Items.Add(host);
        _list.Click += (_, _) => PickSelected();
    }

    public IReadOnlyList<CipherMethod> Items
    {
        get => _items;
        set
        {
            _items = value;
            Refilter(string.Empty, show: false);
        }
    }

    /// <summary>How many entries the picker knows about; a probe for the
    /// automated ui check so an unwired selector never ships again.</summary>
    public int ItemCount => _filtered.Count;

    internal void FocusBox() => _box.Focus();

    /// <summary>Drives the real filter-and-pick pipeline without keyboard
    /// focus: types into the box, walks the list, picks. The automated ui
    /// check uses this because SendKeys needs a foreground window.</summary>
    internal void SimulateTypeAndPick(string query, int arrowDowns = 0)
    {
        _box.Text = query;   // TextChanged filters and opens the popup
        for (var i = 0; i < arrowDowns; i++)
            MoveList(1);
        PickSelected();
    }

    public CipherMethod? Selected { get; private set; }

    public void SetSelectionSilently(CipherMethod method)
    {
        Selected = method;
        _suppress = true;
        _box.Text = $"{method.Name}  -  {method.Category}";
        _suppress = false;
    }

    private void Refilter(bool show) => Refilter(_box.Text, show);

    private void Refilter(string text, bool show)
    {
        var query = text.Trim();
        if (Selected != null && query == $"{Selected.Name}  -  {Selected.Category}")
            query = "";
        _filtered = (query.Length == 0 ? _items : Registry.Search(query)).ToList();
        _list.BeginUpdate();
        _list.Items.Clear();
        foreach (var m in _filtered)
            _list.Items.Add($"{m.Name}  -  {m.Category}");
        _list.EndUpdate();
        if (_filtered.Count > 0)
            _list.SelectedIndex = 0;
        if (show && _filtered.Count > 0)
            ShowPopup();
        else if (show && _filtered.Count == 0)
            _popup.Close();
    }

    private void ShowPopup()
    {
        var host = (ToolStripControlHost)_popup.Items[0]!;
        host.Size = new Size(Math.Max(360, Width), Math.Min(400, Math.Max(1, _list.Items.Count) * _list.ItemHeight + 6));
        _list.SelectedIndex = Math.Max(0, _list.SelectedIndex);
        _popup.Show(this, new Point(0, Height + 1));
        // keep focus on the text box so typing keeps filtering while the
        // list is open; arrow keys and Enter are handled by the box already
    }

    private void OnBoxKeyDown(object? sender, KeyEventArgs e)
    {
        switch (e.KeyCode)
        {
            case Keys.Down:
            case Keys.Up:
                if (!_popup.Visible && _list.Items.Count > 0) ShowPopup();
                MoveList(e.KeyCode == Keys.Down ? 1 : -1);
                e.Handled = true;
                break;
            case Keys.Enter:
                if (_popup.Visible) { PickSelected(); e.Handled = true; }
                break;
            case Keys.Escape:
                _popup.Close();
                e.Handled = true;
                break;
        }
    }

    protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
    {
        if (keyData == (Keys.Control | Keys.A) && _box.Focused)
        {
            _box.SelectAll();
            return true;
        }
        return base.ProcessCmdKey(ref msg, keyData);
    }

    private void MoveList(int delta)
    {
        if (_list.Items.Count == 0) return;
        _list.SelectedIndex = Math.Clamp(_list.SelectedIndex + delta, 0, _list.Items.Count - 1);
    }

    private void PickSelected()
    {
        if (_list.SelectedIndex < 0 || _list.SelectedIndex >= _filtered.Count) return;
        var method = _filtered[_list.SelectedIndex];
        _popup.Close();
        SetSelectionSilently(method);
        MethodPicked?.Invoke(method);
        _box.Focus();
        _box.SelectAll();
    }
}
