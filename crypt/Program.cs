using System;
using System.IO;
using System.Linq;

namespace crypt
{
    class Program
    {
        static void Main(string[] args)
        {
            args = new string[] { "/d", "\\temp\\media\\cavestory" };
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
                    //Create a set of source and destination names
                    string[] Sources = Directory.Exists(Source) ? Directory.GetFiles(Source, "*.*", SearchOption.AllDirectories) : new string[] { Source };
                    Console.Error.WriteLine($"Ready to encrypt {Sources.Length} files");
                    Console.Write("Password: ");
                    string Pass = ReadPassword();
                    if (string.IsNullOrEmpty(Pass))
                    {
                        Console.Error.WriteLine("Aborting on empty password");
                        return;
                    }
                    foreach (var F in Sources)
                    {
                        Console.Error.Write($"{F}...");
                        if (Crypt.EncryptFile(F, F + ".cry", Pass))
                        {
                            if (File.Exists(F))
                            {
                                File.Delete(F);
                            }
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.Error.WriteLine("[DONE]");
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.Error.WriteLine("[ERROR]");
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
                    //Create a set of source and destination names
                    string[] Sources = Directory.Exists(Source) ? Directory.GetFiles(Source, "*.cry", SearchOption.AllDirectories) : new string[] { Source };
                    Console.Error.WriteLine($"Ready to decrypt {Sources.Length} files");
                    Console.Write("Password: ");
                    string Pass = ReadPassword();
                    if (string.IsNullOrEmpty(Pass))
                    {
                        Console.Error.WriteLine("Aborting on empty password");
                        return;
                    }
                    foreach (var F in Sources)
                    {
                        Console.Error.Write($"{F}...");
                        if (Crypt.DecryptFile(F, F.Substring(0, F.Length - 4), Pass))
                        {
                            if (File.Exists(F))
                            {
                                File.Delete(F);
                            }
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.Error.WriteLine("[DONE]");
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.Error.WriteLine("[ERROR]");
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
        }

        private static string ReadPassword()
        {
#if DEBUG
            const string PASS="Test-1234567890";
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

        private static void ShowHelp()
        {
            Console.Error.WriteLine(@"crypt {/e|/d} <input>

/e      - Encrypt the supplied file/directory
/d      - Decrypt the supplied file/directory
input   - Input file/directory");
        }
    }
}
