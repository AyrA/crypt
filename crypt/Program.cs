using System;
using System.IO;
using System.Linq;

namespace crypt
{
    class Program
    {
        static void Main(string[] args)
        {
            //args = new string[] { "/e", @"C:\Temp\media\__test.mp3" };
            args = new string[] { "/d", @"C:\Temp\media\__test.mp3.cry" };

#if DEBUG
            using (var FS = File.OpenRead(args[1]))
            {
                var Hash = Crypt.Hash(FS);
                Console.Error.WriteLine(string.Join("-", Hash.Select(m => m.ToString("X2")).ToArray()));
            }
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
                        switch (Crypt.EncryptFile(F, $"{F}.cry", Pass))
                        {
                            case Crypt.CryptResult.Success:
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.Error.WriteLine("[DONE]");
                                break;
                            default:
                                if (File.Exists($"{F}.cry"))
                                {
                                    File.Delete($"{F}.cry");
                                }
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.Error.WriteLine("[ERROR]");
                                break;
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
                        string Dest = F.Substring(0, F.Length - 4);
                        Console.Error.Write($"{F}...");
                        switch (Crypt.DecryptFile(F, Dest, Pass))
                        {
                            case Crypt.CryptResult.Success:
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.Error.WriteLine("[DONE]");
                                break;
                            default:
                                if (File.Exists(Dest))
                                {
                                    File.Delete(Dest);
                                }
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.Error.WriteLine("[ERROR]");
                                break;
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
