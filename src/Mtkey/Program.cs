using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Mtkey.Core;

namespace Mtkey;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 0 || args[0] == "--demo")
        {
            ParseDemoArgs(args.Skip(1).ToArray(), out var methodId, out var fields, out var text);
            var app = new Application { ShutdownMode = ShutdownMode.OnMainWindowClose };
            var window = new MainWindow(text);
            if (methodId != null) window.SelectMethod(methodId);
            if (fields.Count > 0) window.ApplyDemoFields(fields);
            app.Run(window);
            return 0;
        }

        AttachConsole(ATTACH_PARENT_PROCESS);

        return args[0] switch
        {
            "--selftest" or "-t" => RunSelfTest(),
            "--list" => ListMethods(),
            "--run" => RunHeadless(args[1..]),
            "--smoke" => RunSmoke(),
            "--layoutcheck" => RunLayoutCheck(),
            "--uicheck" => RunUiCheck(),
            "--render" => Render(args[1..]),
            "--help" or "-h" or "-?" => PrintHelp(),
            _ => PrintHelp($"Unknown option {args[0]}."),
        };
    }

    private const int ATTACH_PARENT_PROCESS = -1;

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern bool AttachConsole(int dwProcessId);

    private static int RunSelfTest()
    {
        Console.WriteLine("MTKey self-test");
        Console.WriteLine(new string('=', 60));
        var results = SelfTest.Run();
        var width = Math.Min(46, results.Max(r => r.Name.Length) + 2);
        foreach (var c in results)
        {
            var name = c.Name.Length > width ? c.Name[..width] : c.Name.PadRight(width);
            Console.WriteLine($"{(c.Pass ? "PASS" : "FAIL")}  {name}{c.Detail ?? ""}");
        }
        Console.WriteLine(new string('=', 60));
        var failed = results.Count(c => !c.Pass);
        Console.WriteLine($"{results.Count - failed}/{results.Count} checks passed.");
        return failed == 0 ? 0 : 1;
    }

    private static int ListMethods()
    {
        foreach (var m in Registry.All)
        {
            Console.WriteLine($"{m.Id,-18} {m.Category,-12} {(m.TwoWay ? "two-way " : "one-way ")} {m.Name}");
        }
        return 0;
    }

    private static int RunHeadless(string[] args)
    {
        if (args.Length < 3)
        {
            Console.Error.WriteLine("usage: mtkey --run <method> <encode|decode> [--set name=value ...] <input>");
            return 2;
        }
        var method = Registry.Find(args[0]);
        if (method == null)
        {
            Console.Error.WriteLine($"No method named '{args[0]}'. Try --list.");
            return 2;
        }
        if (!TryParseDirection(args[1], out var direction))
        {
            Console.Error.WriteLine("Direction must be encode or decode (hash, sign, verify, decrypt nicknames work too).");
            return 2;
        }

        var fields = new Dictionary<string, string>();
        var input = "";
        for (var i = 2; i < args.Length; i++)
        {
            if (args[i] == "--set" && i + 1 < args.Length)
            {
                var kv = args[++i].Split('=', 2);
                if (kv.Length == 2) fields[kv[0]] = kv[1];
            }
            else
            {
                input = args[i];
            }
        }
        foreach (var f in method.Fields)
            if (!fields.ContainsKey(f.Name) && f.Default != null)
                fields[f.Name] = f.Default;

        try
        {
            var result = method.Process(new CipherRequest(direction, input, fields));
            if (result.Note != null) Console.Error.WriteLine("note: " + result.Note);
            if (result.Warning != null) Console.Error.WriteLine("warning: " + result.Warning);
            Console.WriteLine(result.Output);
            return 0;
        }
        catch (CipherException ex)
        {
            Console.Error.WriteLine("error: " + ex.Message);
            return 1;
        }
    }

    /// <summary>Maps the friendly direction names methods use on their
    /// buttons onto the two directions the engine speaks.</summary>
    private static bool TryParseDirection(string text, out CipherDirection direction)
    {
        switch (text.Trim().ToLowerInvariant())
        {
            case "encode":
            case "encrypt":
            case "hash":
            case "sign":
            case "build":
            case "wrap":
                direction = CipherDirection.Encode;
                return true;
            case "decode":
            case "decrypt":
            case "verify":
            case "inspect":
            case "unlock":
                direction = CipherDirection.Decode;
                return true;
            default:
                direction = CipherDirection.Encode;
                return false;
        }
    }

    private static int RunSmoke()
    {
        var app = new Application { ShutdownMode = ShutdownMode.OnMainWindowClose };
        var window = new MainWindow { ConfirmExit = false };
        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(1200) };
        timer.Tick += (_, _) => { timer.Stop(); window.Close(); };
        window.Loaded += (_, _) => timer.Start();
        app.Run(window);
        Console.WriteLine("smoke: ui opened and closed cleanly");
        return 0;
    }

    /// <summary>WPF's layout engine cannot overlap children, so this checks
    /// the things it CAN get wrong: starved inputs, crushed text areas and
    /// a starved selector, for every method.</summary>
    private static int RunLayoutCheck()
    {
        var app = new Application();
        var failures = 0;
        var window = new MainWindow();
        window.Show();
        window.ConfirmExit = false;

        foreach (var method in Registry.All)
        {
            window.SelectMethod(method.Id);
            window.UpdateLayout();
            DoEvents();
            foreach (var defect in window.LayoutDefects())
            {
                Console.WriteLine($"LAYOUT {defect}");
                failures++;
            }
        }
        window.Close();
        app.Shutdown();

        Console.WriteLine(failures == 0
            ? $"layout: all {Registry.All.Count} methods render without overlaps"
            : $"layout: {failures} defect(s)");
        return failures == 0 ? 0 : 1;
    }

    private static void DoEvents()
    {
        var frame = new DispatcherFrame();
        Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.Background,
            new DispatcherOperationCallback(f => ((DispatcherFrame)f).Continue = false), frame);
        Dispatcher.PushFrame(frame);
    }

    /// <summary>Drives the selector's real filter-and-pick pipeline and the
    /// swap behavior. Exists because 1.0.2 shipped a selector nobody had
    /// wired up.</summary>
    private static int RunUiCheck()
    {
        var app = new Application();
        var failures = new List<string>();
        var window = new MainWindow();
        window.Show();
        window.ConfirmExit = false;
        DoEvents();

        if (window.FilteredCount != Registry.All.Count)
            failures.Add($"selector lists {window.FilteredCount} methods, expected {Registry.All.Count}");

        window.SetSearchText("sha2");
        DoEvents();
        window.PickFiltered(0);
        DoEvents();
        if (window.CurrentMethodId != "sha256")
            failures.Add($"searching 'sha2' + pick left method '{window.CurrentMethodId}' " +
                         $"(filtered: {window.FilteredCount} first: {window.FilteredFirst} " +
                         $"lastQuery: '{window.LastQuery}' comboText: '{window.ComboText}')");

        window.SetSearchText("defuse");
        DoEvents();
        window.PickFiltered(1);
        DoEvents();
        if (window.CurrentMethodId != "defuse-password")
            failures.Add($"second filtered row over 'defuse' left method '{window.CurrentMethodId}'");

        window.SetSearchText("zzzznope");
        DoEvents();
        window.PickFiltered(0);
        DoEvents();
        if (window.CurrentMethodId != "defuse-password")
            failures.Add("a matchless search changed the method, which it must not");

        window.SetIoForTest("plain body", "cipher body");
        window.SwapForTest();
        DoEvents();
        if (window.InputText != "cipher body" || window.OutputText != "plain body")
            failures.Add("swap did not exchange the two text areas");
        if (window.TopCaption != "Ciphertext" || window.BottomCaption != "Plaintext")
            failures.Add($"swap left captions '{window.TopCaption}' / '{window.BottomCaption}'");

        window.Close();
        app.Shutdown();

        foreach (var f in failures) Console.WriteLine($"UI {f}");
        Console.WriteLine(failures.Count == 0
            ? "ui: selector lists every method and search picks correctly"
            : $"ui: {failures.Count} failure(s)");
        return failures.Count == 0 ? 0 : 1;
    }

    /// <summary>Renders the window offscreen into a PNG for docs and
    /// automated visual checks; no desktop, no focus needed.</summary>
    private static int Render(string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("usage: mtkey --render <out.png> [--method id] [--set name=value ...] [demo text]");
            return 2;
        }
        var png = args[0];
        ParseDemoArgs(args[1..], out var methodId, out var fields, out var text);
        var method = methodId == null ? Registry.All[0] : Registry.Find(methodId);
        if (method == null)
        {
            Console.Error.WriteLine($"No method named '{methodId}'. Try --list.");
            return 2;
        }

        var app = new Application();
        var window = new MainWindow(text) { ConfirmExit = false, WindowStartupLocation = WindowStartupLocation.Manual };
        if (methodId != null) window.SelectMethod(methodId);
        if (fields.Count > 0) window.ApplyDemoFields(fields);
        window.Show();
        DoEvents();
        window.UpdateLayout();
        DoEvents();

        var width = (int)Math.Ceiling(window.ActualWidth);
        var height = (int)Math.Ceiling(window.ActualHeight);
        var rtb = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        rtb.Render(window);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(rtb));
        using (var fs = File.Create(png))
        {
            encoder.Save(fs);
        }
        window.Close();
        app.Shutdown();
        Console.WriteLine($"rendered {width}x{height} to {png}");
        return 0;
    }

    /// <summary>Shared parsing for --demo/--render: an optional --method id,
    /// any number of --set name=value pairs, and the trailing demo text.</summary>
    private static void ParseDemoArgs(string[] args, out string? methodId,
        out Dictionary<string, string> fields, out string text)
    {
        methodId = null;
        fields = new Dictionary<string, string>();
        var words = new List<string>();
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--method" && i + 1 < args.Length)
                methodId = args[++i];
            else if (args[i] == "--set" && i + 1 < args.Length)
            {
                var kv = args[++i].Split('=', 2);
                if (kv.Length == 2) fields[kv[0]] = kv[1];
            }
            else
                words.Add(args[i]);
        }
        text = words.Count > 0 ? string.Join(' ', words) : "Attack at dawn!";
    }

    private static int PrintHelp(string? error = null)
    {
        if (error != null) Console.Error.WriteLine(error);
        Console.WriteLine("""
            MTKey, a cipher workbench.

            usage:
              mtkey                       open the GUI
              mtkey --selftest            run all known-answer and roundtrip checks
              mtkey --list                list every cipher method
              mtkey --run <id> <dir> [--set name=value ...] <input>
                                          run one method from the command line
              mtkey --smoke               open and close the UI (automation check)
              mtkey --layoutcheck         measure every method's layout
              mtkey --uicheck             drive search, pick and swap
              mtkey --render <out.png> [--method id] [--set name=value ...] [text]

            examples:
              mtkey --run base64 encode "hello world"
              mtkey --run caesar encode --set shift=13 "et tu, brute?"
              mtkey --run sha256 hash "abc"
            """);
        return error == null ? 0 : 2;
    }
}
