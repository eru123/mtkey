using Mtkey.Core;

namespace Mtkey;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 0 || args[0] == "--demo")
        {
            ApplicationConfiguration.Initialize();
            ParseDemoArgs(args.Skip(1).ToArray(), out var methodId, out var fields, out var text);
            var form = new MainForm(text);
            if (methodId != null) form.SelectMethod(methodId);
            if (fields.Count > 0) form.ApplyDemoFields(fields);
            Application.Run(form);
            return 0;
        }

        // GUI subsystem binaries have no console of their own; borrow the one
        // that launched us so --selftest output shows up in a terminal.
        AttachConsole(ATTACH_PARENT_PROCESS);

        return args[0] switch
        {
            "--selftest" or "-t" => RunSelfTest(),
            "--list" => ListMethods(),
            "--run" => RunHeadless(args[1..]),
            "--smoke" => RunSmoke(),
            "--layoutcheck" => RunLayoutCheck(),
            "--render" => Render(args[1..]),
            "--help" or "-h" or "-?" => PrintHelp(),
            _ => PrintHelp($"Unknown option {args[0]}."),
        };
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

    /// <summary>Paints the window into a PNG without needing a screenshot of
    /// the desktop; handy for docs and automated layout checks.</summary>
    private static int Render(string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("usage: mtkey --render <out.png> [--method id] [demo text]");
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
        ApplicationConfiguration.Initialize();
        var form = new MainForm(text);
        form.SelectMethod(method.Id);
        if (fields.Count > 0) form.ApplyDemoFields(fields);
        form.Show();
        Application.DoEvents();
        System.Threading.Thread.Sleep(700);
        Application.DoEvents();
        using var bmp = new Bitmap(form.Width, form.Height);
        form.DrawToBitmap(bmp, new Rectangle(0, 0, form.Width, form.Height));
        bmp.Save(png, System.Drawing.Imaging.ImageFormat.Png);
        return 0;
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
    /// buttons (hash, sign, verify, decrypt, inspect...) onto the two
    /// directions the engine speaks.</summary>
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

    /// <summary>Opens the UI against every method and fails if any parameter
    /// row overlaps or any text area gets crushed. Guards the layout
    /// regression that shipped in 1.0.0.</summary>
    private static int RunLayoutCheck()
    {
        ApplicationConfiguration.Initialize();
        var failures = 0;
        using (var form = new MainForm())
        {
            form.Show();
            foreach (var method in Registry.All)
            {
                form.SelectMethod(method.Id);
                form.RunLayoutPass();
                var defects = form.LayoutDefects();
                foreach (var d in defects)
                    Console.WriteLine($"LAYOUT {d}");
                if (defects.Count > 0) failures++;
            }
        }
        Console.WriteLine(failures == 0
            ? $"layout: all {Registry.All.Count} methods render without overlaps"
            : $"layout: {failures} method(s) with layout defects");
        return failures == 0 ? 0 : 1;
    }

    private static int RunSmoke()
    {
        ApplicationConfiguration.Initialize();
        var form = new MainForm();
        var timer = new System.Windows.Forms.Timer { Interval = 1200 };
        timer.Tick += (_, _) => { timer.Stop(); form.Close(); };
        form.Shown += (_, _) => timer.Start();
        Application.Run(form);
        Console.WriteLine("smoke: ui opened and closed cleanly");
        return 0;
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

            examples:
              mtkey --run base64 encode "hello world"
              mtkey --run caesar encode --set shift=13 "et tu, brute?"
              mtkey --run sha256 hash "abc"
            """);
        return error == null ? 0 : 2;
    }
}
