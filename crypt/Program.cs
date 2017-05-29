using System;
using System.IO;
using System.Linq;

namespace crypt
{
    class Program
    {
        static void Main(string[] args)
        {

#if DEBUG
            args = new string[] { "/e", @"C:\temp\media" };
            //args = new string[] { "/d", @"C:\temp\media\CRY" };
#endif

            if (args.Length == 0 || args.Contains("/?"))
            {
                ShowHelp();
            }
            #region ENCRYPT
            //process encryption part
            else if (args.Select(m => m.ToLower()).Contains("/e"))
            {
                //get rid of '/e'
                args = args.Where(m => m.ToLower() != "/e").ToArray();
                if (args.Length > 0)
                {
                    string Source = Path.GetFullPath(args[0]);
                    if (!File.Exists(Source) && !Directory.Exists(Source))
                    {
                        Console.Error.WriteLine($"{Source} is neither file nor directory");
                        ShowHelp();
                        return;
                    }
                    var Sources = ScanDir(Source);
                    if (Sources == null)
                    {
                        return;
                    }

                    Console.Error.WriteLine($"Ready to encrypt {Sources.Length} files");
                    Console.Write("Password: ");
                    Console.ForegroundColor = ConsoleColor.White;
                    string Pass = ReadPassword();
                    Console.ResetColor();
                    if (string.IsNullOrEmpty(Pass))
                    {
                        Console.Error.WriteLine("Aborting on empty password");
                        return;
                    }

                    Console.Error.WriteLine(@"Fast or safe?
Fast will use a smaller difficulty value in the password processor.
Encrypting and decrypting is faster this way.
The algorithm type is the same but password brute force is faster.
The speed penalty is the same regardless of file size.
Fast is not unsafe.
The minimum recommended difficulty in the standard is 1000,
we use 10 times that for 'Fast' and 50 times that for 'Safe'");
                    Console.ForegroundColor = ConsoleColor.White;
                    int Cycles = Ask("Fast or Safe?", "FS") == 'F' ? 10000 : 50000;
                    Console.ResetColor();

                    var C = new Crypt();
                    foreach (var F in Sources)
                    {
                        Console.Error.Write($"{F}...");
                        C.GenerateSalt();
                        C.GeneratePassword(Pass, Cycles);
                        using (var IN = File.OpenRead(F))
                        {
                            using (var OUT = File.Create($"{F}.cry"))
                            {
                                Crypt.CryptResult CR;
                                switch (CR = C.Encrypt(IN, OUT))
                                {
                                    case Crypt.CryptResult.Success:
                                        IN.Close();
                                        try
                                        {
                                            File.Delete(F);
                                            Console.ForegroundColor = ConsoleColor.Green;
                                            Console.Error.WriteLine("[DONE]");
                                        }
                                        catch
                                        {
                                            Console.ForegroundColor = ConsoleColor.Yellow;
                                            Console.Error.WriteLine("[DELETE ERROR]");
                                        }
                                        break;
                                    default:
                                        OUT.Close();
                                        if (File.Exists($"{F}.cry"))
                                        {
                                            File.Delete($"{F}.cry");
                                        }
                                        Console.ForegroundColor = ConsoleColor.Red;
                                        Console.Error.WriteLine($"[ERROR: {CR}]");
                                        break;
                                }
                            }
                        }
                        Console.ResetColor();
                    }
                }
                else
                {
                    Console.Error.WriteLine("Missing source file/directory argument");
                    ShowHelp();
                    return;
                }
            }
            #endregion
            #region DECRYPT
            //process decryption part
            else if (args.Select(m => m.ToLower()).Contains("/d"))
            {
                //get rid of '/d'
                args = args.Where(m => m.ToLower() != "/d").ToArray();
                if (args.Length > 0)
                {
                    string Source = Path.GetFullPath(args[0]);
                    if (!File.Exists(Source) && !Directory.Exists(Source))
                    {
                        Console.Error.WriteLine($"{Source} is neither file nor directory");
                        ShowHelp();
                        return;
                    }
                    var Sources = ScanDir(Source, "*.cry");
                    if (Sources == null)
                    {
                        return;
                    }
                    Console.Error.WriteLine($"Ready to decrypt {Sources.Length} files");
                    Console.Write("Password: ");
                    string Pass = ReadPassword();
                    if (string.IsNullOrEmpty(Pass))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.Error.WriteLine("Aborting on empty password");
                        Console.ResetColor();
                        return;
                    }
                    var C = new Crypt();
                    foreach (var F in Sources)
                    {
                        string Dest = F.Substring(0, F.Length - 4);
                        Console.Error.Write($"{F}...");
                        using (var IN = File.OpenRead(F))
                        {
                            using (var OUT = File.Create(Dest))
                            {
                                Crypt.CryptResult CR;
                                switch (CR = C.Decrypt(IN, OUT, Pass))
                                {
                                    case Crypt.CryptResult.Success:
                                        IN.Close();
                                        try
                                        {
                                            File.Delete(F);
                                            Console.ForegroundColor = ConsoleColor.Green;
                                            Console.Error.WriteLine("[DONE]");
                                        }
                                        catch
                                        {
                                            Console.ForegroundColor = ConsoleColor.Yellow;
                                            Console.Error.WriteLine("[DELETE ERROR]");
                                        }
                                        break;
                                    default:
                                        OUT.Close();
                                        if (File.Exists(Dest))
                                        {
                                            File.Delete(Dest);
                                        }
                                        Console.ForegroundColor = ConsoleColor.Red;
                                        Console.Error.WriteLine($"[ERROR {CR}]");
                                        break;
                                }
                            }
                        }
                        Console.ResetColor();
                    }
                }
                else
                {
                    Console.Error.WriteLine("Missing mode argument: /d or /e");
                    ShowHelp();
                    return;
                }
            }
            #endregion
            else
            {
                ShowHelp();
            }

#if DEBUG
            Console.Error.WriteLine("#END");
            Console.ReadKey(true);
#endif
        }

        private static string[] ScanDir(string Dir, string Pattern = "*.*")
        {
            Console.Error.Write("Scanning Files...");
            //Create a set of source and destination names
            string[] Sources = null;
            try
            {
                Sources = Directory.Exists(Dir) ? Directory.GetFiles(Dir, Pattern, SearchOption.AllDirectories) : new string[] { Dir };
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Error.WriteLine("[DONE]");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Error.WriteLine("[ERROR]");
                Console.Error.WriteLine($"Can't scan directory structure: {ex}");
            }
            Console.ResetColor();
            return Sources;
        }

        private static char Ask(string Text, string Values)
        {
            char[] Available = Values.ToCharArray();
            Console.Error.Write("{0} [{1}]?", Text, string.Join("/", Available));
            Available = Available.Select(m => m.ToString().ToLower()[0]).ToArray();
            while (true)
            {
                var C = Console.ReadKey(true).KeyChar;
                if (Available.Contains(C.ToString().ToLower()[0]))
                {
                    Console.Error.WriteLine();
                    return C;
                }
            }
        }

        /// <summary>
        /// Reads a password from STDIN and masks it.
        /// It's incompatible with stream redirection.
        /// </summary>
        /// <returns>User supplied password</returns>
        private static string ReadPassword()
        {
#if DEBUG
            const string PASS = "Test-1234567890";
            Console.Error.WriteLine(string.Empty.PadRight(PASS.Length, '*'));
            return PASS;
#else
            string pass = "";
            while (true)
            {
                var Key = Console.ReadKey(true);
                switch (Key.Key)
                {
                    case ConsoleKey.Enter:
                        Console.WriteLine();
                        return pass;
                    case ConsoleKey.Backspace:
                        if (pass.Length > 0)
                        {
                            pass = pass.Substring(0, pass.Length - 1);
                            Console.Write("\b \b");
                        }
                        else
                        {
                            Console.Beep();
                        }
                        break;
                    default:
                        if (!char.IsControl(Key.KeyChar) && pass.Length < 40)
                        {
                            pass += Key.KeyChar;
                            Console.Write('*');
                        }
                        else
                        {
                            Console.Beep();
                        }
                        break;
                }
            }
#endif
        }

        /// <summary>
        /// Prints the help
        /// </summary>
        private static void ShowHelp()
        {
            Console.Error.WriteLine(@"crypt {/e|/d} <input>

/e      - Encrypt the supplied file/directory
/d      - Decrypt the supplied file/directory
input   - Input file/directory");
        }
    }
}
