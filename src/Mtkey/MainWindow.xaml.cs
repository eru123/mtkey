using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Mtkey.Core;

namespace Mtkey;

/// <summary>
/// The workbench window. Layout lives in MainWindow.xaml as a five row grid
/// (menu, header, parameters, flexible text split, status bar); this class
/// only wires behavior onto it.
/// </summary>
public partial class MainWindow : Window
{
    private static readonly Brush StatusBrush = Brushes.Gray;
    private static readonly Brush NoteBrush = Brushes.ForestGreen;
    private static readonly Brush WarnBrush = Brushes.DarkOrange;
    private static readonly Brush ErrorBrush = Brushes.Firebrick;

    private CipherMethod _method = Registry.All[0];
    private CipherDirection _direction = CipherDirection.Encode;
    private bool _suppressCombo;
    private readonly Dictionary<string, FrameworkElement> _fieldControls = new();
    private readonly Dictionary<string, TextBlock> _fieldLabels = new();
    private readonly Dictionary<string, FieldSpec> _fieldSpecs = new();
    private readonly DispatcherTimer _debounce;
    private ListCollectionView _comboView = null!;

    /// <summary>Automated runs clear this so closing never blocks on the
    /// exit prompt.</summary>
    public bool ConfirmExit { get; set; } = true;

    public MainWindow(string? demoInput = null)
    {
        InitializeComponent();
        CountText.Text = $"{Registry.All.Count} methods";

        _debounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(220) };
        _debounce.Tick += (_, _) => { _debounce.Stop(); ValidateLive(); ProcessNow(); };

        // a maximized state would ignore our max bounds, so cancel it; the
        // maximize button is also disabled by disabling its system command
        StateChanged += (_, _) =>
        {
            if (WindowState == WindowState.Maximized) WindowState = WindowState.Normal;
        };
        SourceInitialized += (_, _) =>
        {
            var helper = new System.Windows.Interop.WindowInteropHelper(this);
            System.Windows.Interop.HwndSource.FromHwnd(helper.Handle)?.AddHook(WndProc);
        };
        Closing += ConfirmExitBeforeClose;

        var methods = Registry.All.ToList();
        _comboView = new ListCollectionView(methods)
        {
            Filter = o => FilterMethod((CipherMethod)o),
        };
        MethodSelector.ItemsSource = _comboView;
        MethodSelector.SelectedIndex = 0;
        _comboView.Refresh(); // evaluate the filter once with the display text in place

        SwitchMethod(methods[0]);

        if (demoInput != null)
        {
            InputBox.Text = demoInput;
            Schedule();
        }
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        const int WM_SYSCOMMAND = 0x0112;
        const int SC_MAXIMIZE = 0xF030;
        if (msg == WM_SYSCOMMAND && wParam.ToInt64() == SC_MAXIMIZE)
        {
            handled = true; // no maximize, resize only within bounds
        }
        return IntPtr.Zero;
    }

    private void ConfirmExitBeforeClose(object? sender, CancelEventArgs e)
    {
        if (!ConfirmExit) return;
        var choice = MessageBox.Show(this,
            "Are you sure you want to exit MTKey?", "Exit MTKey",
            MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (choice == MessageBoxResult.No)
            e.Cancel = true;
    }

    // ------------------------------------------------------------ selector

    private bool FilterMethod(CipherMethod m)
    {
        var q = MethodSelector.Text.Trim();
        LastQuery = q;
        // the display text of the current selection is not a query
        if (MethodSelector.SelectedItem is CipherMethod selected &&
            q == (selected.ToString() ?? selected.Name))
            return true;
        if (q.Length == 0) return true;
        return Registry.Search(q).Contains(m);
    }

    /// <summary>Last query the filter saw; probe for --uicheck.</summary>
    public string LastQuery { get; private set; } = "";
    public string ComboText => MethodSelector.Text;

    private void MethodSelector_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_suppressCombo) return;
        _comboView.Refresh();
        MethodSelector.IsDropDownOpen = MethodSelector.IsKeyboardFocusWithin
            && MethodSelector.Items.Count > 0
            && MethodSelector.Items.Count < Registry.All.Count;
    }

    private void Method_Selected(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressCombo) return;
        if (MethodSelector.SelectedItem is not CipherMethod method) return;
        SetComboText(method.ToString() ?? method.Name);
        SwitchMethod(method);
    }

    private void SetComboText(string text)
    {
        _suppressCombo = true;
        MethodSelector.Text = text;
        _suppressCombo = false;
    }

    // ------------------------------------------------------------ methods

    private void SwitchMethod(CipherMethod method)
    {
        _method = method;
        // the description line doubles as the one-way notice, so the header
        // row never carries variable-width interactive text
        BlurbText.Text = method.TwoWay
            ? method.Blurb
            : $"One-way street: {method.EncodeLabel} only, no way back. {method.Blurb}";
        BlurbText.ToolTip = method.Blurb + "\n\nClick for the full explanation.";
        var wikiLabel = method.Category == "Defuse PHP" ? "GitHub" : "Wikipedia";
        WikiButton.Content = wikiLabel;
        WikiMenuItem.Header = $"Open {wikiLabel} page";

        if (method.TwoWay)
        {
            ModePanel.Visibility = Visibility.Visible;
            EncodeRadio.Content = method.EncodeLabel;
            DecodeRadio.Content = method.DecodeLabel;
            EncodeRadio.IsChecked = true;
        }
        else
        {
            ModePanel.Visibility = Visibility.Collapsed;
        }

        RebuildParams();
        PlaintextGroup.Header = "Plaintext";
        CiphertextGroup.Header = method.TwoWay ? "Ciphertext" : "Hash";
        _direction = CipherDirection.Encode;
        Schedule();
    }

    private void RebuildParams()
    {
        _fieldControls.Clear();
        _fieldLabels.Clear();
        _fieldSpecs.Clear();
        ParamsGrid.Children.Clear();
        ParamsGrid.RowDefinitions.Clear();

        var row = 0;
        foreach (var spec in _method.Fields)
        {
            ParamsGrid.RowDefinitions.Add(new RowDefinition { Height = spec.Kind == FieldKind.Multiline
                ? new GridLength(64)
                : GridLength.Auto });

            var label = new TextBlock
            {
                Text = spec.Label,
                VerticalAlignment = VerticalAlignment.Center,
                TextTrimming = TextTrimming.CharacterEllipsis,
            };
            ToolTipService.SetToolTip(label, spec.Hint ?? spec.Label);
            Grid.SetRow(label, row);
            Grid.SetColumn(label, 0);
            ParamsGrid.Children.Add(label);
            _fieldLabels[spec.Name] = label;
            _fieldSpecs[spec.Name] = spec;

            FrameworkElement input = spec.Kind switch
            {
                FieldKind.Dropdown => new ComboBox
                {
                    ItemsSource = spec.Options,
                    Height = 24,
                    Margin = new Thickness(2, 2, 2, 2),
                    VerticalContentAlignment = VerticalAlignment.Center,
                },
                FieldKind.Number => new TextBox
                {
                    Height = 24,
                    Margin = new Thickness(2, 2, 2, 2),
                    Text = spec.Default ?? "",
                },
                FieldKind.Multiline => NewMonoBox(multiline: true),
                _ => spec.Secret ? NewPasswordBox() : NewMonoBox(multiline: false),
            };
            switch (input)
            {
                case TextBox tb:
                    if (spec.Kind != FieldKind.Multiline && spec.Kind != FieldKind.Number)
                        tb.Text = spec.Default ?? "";
                    tb.TextChanged += (_, _) => Schedule();
                    break;
                case PasswordBox pb:
                    pb.Password = spec.Default ?? "";
                    pb.PasswordChanged += (_, _) => Schedule();
                    break;
                case ComboBox combo:
                    if (spec.Default != null) combo.SelectedItem = spec.Default;
                    else if (combo.Items.Count > 0) combo.SelectedIndex = 0;
                    combo.SelectionChanged += (_, _) => Schedule();
                    break;
            }
            if (spec.Hint != null) ToolTipService.SetToolTip(input, spec.Hint);
            Grid.SetRow(input, row);
            Grid.SetColumn(input, 1);
            ParamsGrid.Children.Add(input);
            _fieldControls[spec.Name] = input;

            if (spec.Generator != null)
            {
                var dice = new Button
                {
                    Content = "🎲",
                    Height = 24,
                    Margin = new Thickness(2, 2, 0, 2),
                    Padding = new Thickness(0),
                };
                ToolTipService.SetToolTip(dice, "Roll a random value");
                var captured = spec.Name;
                dice.Click += (_, _) => Roll(captured);
                Grid.SetRow(dice, row);
                Grid.SetColumn(dice, 2);
                ParamsGrid.Children.Add(dice);
            }
            row++;
        }

        if (_method.Fields.Any(f => f.Generator != null))
        {
            ParamsGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var tip = new TextBlock
            {
                Text = "Tip: the dice button rolls a fresh random value; on RSA it mints the key pair.",
                FontSize = 11,
                Foreground = Brushes.Gray,
                Margin = new Thickness(0, 2, 0, 0),
            };
            Grid.SetRow(tip, row);
            Grid.SetColumnSpan(tip, 3);
            ParamsGrid.Children.Add(tip);
            row++;
        }

        ParamsGroup.Visibility = _method.Fields.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private static TextBox NewMonoBox(bool multiline) => new()
    {
        FontFamily = new FontFamily("Consolas"),
        FontSize = 12,
        Height = multiline ? 60 : 24,
        Margin = new Thickness(2, 2, 2, 2),
        AcceptsReturn = multiline,
        TextWrapping = TextWrapping.NoWrap,
        VerticalScrollBarVisibility = multiline ? ScrollBarVisibility.Auto : ScrollBarVisibility.Hidden,
        VerticalContentAlignment = multiline ? VerticalAlignment.Top : VerticalAlignment.Center,
    };

    private static PasswordBox NewPasswordBox() => new()
    {
        Height = 24,
        Margin = new Thickness(2, 2, 2, 2),
    };

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
                    case PasswordBox pb:
                        pb.Password = value;
                        break;
                    case ComboBox cb:
                        if (cb.Items.Contains(value)) cb.SelectedItem = value;
                        break;
                }
            }
            ValidateLive();
            Schedule();
        }
        catch (CipherException ex)
        {
            SetStatus(ex.Message, ErrorBrush);
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
                PasswordBox pb => pb.Password,
                ComboBox cb => cb.SelectedItem?.ToString() ?? "",
                _ => "",
            };
        }
        return values;
    }

    // ------------------------------------------------------------ engine

    private void Schedule()
    {
        _debounce.Stop();
        _debounce.Start();
    }

    private void Mode_Changed(object sender, RoutedEventArgs e)
    {
        if (EncodeRadio.IsChecked == true) _direction = CipherDirection.Encode;
        else if (DecodeRadio.IsChecked == true) _direction = CipherDirection.Decode;
        else return;
        if (IsLoaded) Schedule();
    }

    private void Execute_Click(object sender, RoutedEventArgs e)
    {
        ValidateLive();
        ProcessNow();
    }

    private void Input_TextChanged(object sender, TextChangedEventArgs e) => Schedule();

    private void ValidateLive()
    {
        var validation = _method.ValidateFields(CollectFields());
        foreach (var (field, verdict) in validation.Fields)
        {
            if (!_fieldLabels.TryGetValue(field, out var label)) continue;
            if (!_fieldSpecs.TryGetValue(field, out var spec)) continue;
            label.Text = verdict.Certain
                ? spec.Label + (verdict.Ok ? " ✔" : " ✖")
                : spec.Label;
            label.Foreground = verdict.Certain
                ? (verdict.Ok ? NoteBrush : ErrorBrush)
                : Brushes.Black;
            ToolTipService.SetToolTip(label, verdict.Certain ? verdict.Message : spec.Hint ?? spec.Label);
        }
        if (validation.Overall.Length > 0)
        {
            var bad = validation.Fields.Values.Any(v => v.Certain && !v.Ok);
            SetStatus(validation.Overall, bad ? ErrorBrush : NoteBrush);
        }
    }

    private void ProcessNow()
    {
        try
        {
            var result = _method.Process(new CipherRequest(_direction, InputBox.Text, CollectFields()));
            OutputBox.Text = result.Output;
            if (result.Warning != null) SetStatus(result.Warning, WarnBrush);
            else if (result.Note != null) SetStatus(result.Note, NoteBrush);
            else if (StatusText.Foreground != StatusBrush) SetStatus("Ready.", StatusBrush);
        }
        catch (CipherException ex)
        {
            SetStatus(ex.Message, ErrorBrush);
        }
        catch (FormatException)
        {
            SetStatus("The result is binary bytes, not valid text. The hex methods will show every byte instead.", ErrorBrush);
        }
        catch (Exception ex)
        {
            SetStatus($"Unexpected: {ex.Message}", ErrorBrush);
        }
    }

    private void SwapSides()
    {
        (InputBox.Text, OutputBox.Text) = (OutputBox.Text, InputBox.Text);
        (PlaintextGroup.Header, CiphertextGroup.Header) = (CiphertextGroup.Header, PlaintextGroup.Header);
        Schedule();
        InputBox.Focus();
        InputBox.CaretIndex = InputBox.Text.Length;
    }

    private void SetStatus(string text, Brush brush)
    {
        StatusText.Text = text;
        StatusText.Foreground = brush;
    }

    // ------------------------------------------------------------ actions

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        if (OutputBox.Text.Length == 0) return;
        try
        {
            Clipboard.SetText(OutputBox.Text);
            SetStatus("Copied to clipboard.", NoteBrush);
        }
        catch (Exception)
        {
            SetStatus("Clipboard refused; select the text and press Ctrl+C.", WarnBrush);
        }
    }

    private void Swap_Click(object sender, RoutedEventArgs e) => SwapSides();

    private void Clear_Click(object sender, RoutedEventArgs e)
    {
        InputBox.Clear();
        OutputBox.Clear();
        Schedule();
    }

    private void Exit_Click(object sender, RoutedEventArgs e) => Close();

    private void OpenWiki_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo(_method.WikiUrl) { UseShellExecute = true });
        }
        catch (Exception)
        {
            SetStatus($"Could not open the browser: {_method.WikiUrl}", ErrorBrush);
        }
    }

    private void MethodHelp_Click(object sender, RoutedEventArgs e)
    {
        var wiki = _method.Category == "Defuse PHP" ? "Project" : "Wikipedia";
        MessageBox.Show(this,
            $"{_method.Name} ({_method.Category})\n\n{_method.Blurb}\n\n{_method.Learn}\n\n" +
            $"{wiki}: {_method.WikiUrl}",
            _method.Name, MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void About_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show(this,
            "MTKey 1.0.8\nA cipher workbench: encode, decode, hash, sign, and learn.\n" +
            $"{Registry.All.Count} methods. MIT licensed.\nhttps://github.com/eru123/mtkey",
            "About MTKey", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void SelfTest_Click(object sender, RoutedEventArgs e)
    {
        SetStatus("Running self-test...", Brushes.Black);
        var results = SelfTest.Run();
        var failed = results.Count(c => !c.Pass);
        if (failed == 0)
            MessageBox.Show(this, $"{results.Count}/{results.Count} checks passed.",
                "Self-test", MessageBoxButton.OK, MessageBoxImage.Information);
        else
            MessageBox.Show(this,
                string.Join("\n", results.Where(c => !c.Pass).Select(c => $"FAIL {c.Name}: {c.Detail}")),
                $"Self-test: {failed} failures", MessageBoxButton.OK, MessageBoxImage.Warning);
        SetStatus("Ready.", StatusBrush);
    }

    // -------------------------------------------------- probes for checks

    /// <summary>Used by --demo/--render/--uicheck to land on one method.</summary>
    public void SelectMethod(string id)
    {
        var method = Registry.Find(id);
        if (method == null) return;
        SetComboText(method.ToString() ?? method.Name);
        SwitchMethod(method);
    }

    /// <summary>Types into the search box, driving the real filter pipeline.</summary>
    public void SetSearchText(string text)
    {
        MethodSelector.Text = text;
        _comboView.Refresh();
    }

    public int FilteredCount => _comboView.Count;

    public string FilteredFirst =>
        _comboView.Count > 0 ? ((CipherMethod)_comboView.GetItemAt(0)!).Id : "(none)";

    /// <summary>Picks the filtered row at an index; -1 picks nothing.
    /// Selects by item, since SelectedIndex does not track the filtered
    /// view reliably on an editable combo.</summary>
    public void PickFiltered(int index)
    {
        if (index < 0 || index >= _comboView.Count) return;
        MethodSelector.SelectedItem = _comboView.GetItemAt(index);
    }

    /// <summary>Fills parameter fields; used by --demo/--render.</summary>
    public void ApplyDemoFields(IReadOnlyDictionary<string, string> fields)
    {
        foreach (var (name, value) in fields)
        {
            if (!_fieldControls.TryGetValue(name, out var control)) continue;
            switch (control)
            {
                case TextBox tb:
                    tb.Text = value;
                    break;
                case PasswordBox pb:
                    pb.Password = value;
                    break;
                case ComboBox cb:
                    if (cb.Items.Contains(value)) cb.SelectedItem = value;
                    break;
            }
        }
        Schedule();
    }

    // probes for --uicheck
    public string CurrentMethodId => _method.Id;
    public string InputText => InputBox.Text;
    public string OutputText => OutputBox.Text;
    public string TopCaption => (string)PlaintextGroup.Header;
    public string BottomCaption => (string)CiphertextGroup.Header;
    public void SetIoForTest(string input, string output)
    {
        InputBox.Text = input;
        OutputBox.Text = output;
    }
    public void SwapForTest() => SwapSides();

    /// <summary>Reports layout problems the WPF engine cannot create by
    /// itself but bad sizing constants can: starved inputs, crushed text
    /// areas, a starved selector. Drives --layoutcheck.</summary>
    public List<string> LayoutDefects()
    {
        var defects = new List<string>();
        if (InputBox.ActualHeight < 36)
            defects.Add($"{_method.Id}: input box crushed to {InputBox.ActualHeight:0}px");
        if (OutputBox.ActualHeight < 36)
            defects.Add($"{_method.Id}: output box crushed to {OutputBox.ActualHeight:0}px");
        if (MethodSelector.ActualWidth < 200)
            defects.Add($"{_method.Id}: selector is only {MethodSelector.ActualWidth:0}px wide");
        foreach (var (name, control) in _fieldControls)
        {
            if (control.ActualWidth < 100)
                defects.Add($"{_method.Id}: field '{name}' input is only {control.ActualWidth:0}px wide");
        }
        return defects;
    }
}
