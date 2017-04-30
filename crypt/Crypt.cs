using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace crypt
{
    public class Crypt
    {
        public const string HASHALG = "SHA256";
        public const string HEADER = "ACRYPT";

        public static bool EncryptFile(string Filename, string DestinationName, string Password)
        {
            if (IsEncrypted(Filename))
            {
                File.Move(Filename, DestinationName);
            }
            else
            {
                using (Rijndael R = Rijndael.Create())
                {
                    R.GenerateIV();
                    int KeySize = R.LegalKeySizes.OrderByDescending(m => m.MaxSize).First().MaxSize / 8;
                    byte[] Salt = RandomBytes(KeySize);
                    byte[] Key = DeriveBytes(Password, KeySize, Salt);
                    byte[] Hash = GerPasswordByteHash(Key);
                    using (var IN = File.OpenRead(Filename))
                    {
                        using (var FS = File.Create(DestinationName))
                        {
                            //Write Header
                            using (var BW = new BinaryWriter(FS, Encoding.UTF8, true))
                            {
                                BW.Write(Encoding.UTF8.GetBytes(HEADER));
                                BW.Write(Salt.Length);
                                BW.Write(Salt);
                                BW.Write(R.IV.Length);
                                BW.Write(R.IV);
                                BW.Write(Hash.Length);
                                BW.Write(Hash);

                                BW.Flush();
                            }
                            using (CryptoStream CS = new CryptoStream(FS, R.CreateEncryptor(Key, R.IV), CryptoStreamMode.Write))
                            {
                                try
                                {
                                    IN.CopyTo(CS, R.BlockSize * 100);
                                }
                                catch
                                {
                                    return false;
                                }
                            }
                        }
                    }
                }
            }
            return true;
        }

        public static bool DecryptFile(string Filename, string DestinationName, string Password)
        {
            if (File.Exists(Filename) && !IsEncrypted(Filename))
            {
                File.Move(Filename, DestinationName);
                return true;
            }
            using (Rijndael R = Rijndael.Create())
            {
                int KeySize = R.LegalKeySizes.OrderByDescending(m => m.MaxSize).First().MaxSize / 8;
                R.GenerateIV();
                using (var IN = File.OpenRead(Filename))
                {
                    byte[] Salt = null;
                    byte[] IV = null;
                    byte[] Hash = null;
                    using (var BR = new BinaryReader(IN, Encoding.UTF8, true))
                    {
                        if (Encoding.UTF8.GetString(BR.ReadBytes(HEADER.Length)) != HEADER)
                        {
                            return false;
                        }
                        try
                        {
                            Salt = BR.ReadBytes(BR.ReadInt32());
                            IV = BR.ReadBytes(BR.ReadInt32());
                            Hash = BR.ReadBytes(BR.ReadInt32());
                        }
                        catch
                        {
                            return false;
                        }
                    }
                    R.IV = IV;
                    byte[] Key = DeriveBytes(Password, KeySize, Salt);

                    if (!CheckPasswordBytes(Key, Hash))
                    {
                        return false;
                    }

                    using (var FS = File.Create(DestinationName))
                    {
                        try
                        {
                            using (CryptoStream CS = new CryptoStream(IN, R.CreateDecryptor(Key, R.IV), CryptoStreamMode.Read))
                            {
                                CS.CopyTo(FS, R.BlockSize * 100);
                            }
                        }
                        catch
                        {
                            return false;
                        }
                    }
                }
            }
            return true;
        }

        private static byte[] GerPasswordByteHash(byte[] Password)
        {
            using (var A = HashAlgorithm.Create(HASHALG))
            {
                return A.ComputeHash(Password);
            }
        }

        private static bool CheckPasswordBytes(byte[] Password, byte[] Hash)
        {
            var H = GerPasswordByteHash(Password);
            for (var i = 0; i < H.Length; i++)
            {
                if (H[i] != Hash[i])
                {
                    return false;
                }
            }
            return true;
        }

        public static bool IsEncrypted(string Filename)
        {
            var ret = File.Exists(Filename);
            if (ret)
            {
                using (var FS = File.OpenRead(Filename))
                {
                    using (var BR = new BinaryReader(FS))
                    {
                        if (Encoding.UTF8.GetString(BR.ReadBytes(HEADER.Length)) != HEADER)
                        {
                            return false;
                        }
                        try
                        {
                            //Read 3 byte arrays from the file (IV,Salt,Hash)
                            BR.ReadBytes(BR.ReadInt32());
                            BR.ReadBytes(BR.ReadInt32());
                            BR.ReadBytes(BR.ReadInt32());
                        }
                        catch
                        {
                            return false;
                        }
                    }
                }
            }
            return ret;
        }

        private static byte[] RandomBytes(int Count)
        {
            byte[] Data = new byte[Count];
            using (RNGCryptoServiceProvider RNG = (RNGCryptoServiceProvider)RandomNumberGenerator.Create())
            {
                RNG.GetBytes(Data);
            }
            return Data;
        }

        private static byte[] DeriveBytes(string Password, int NumberOfBytes, byte[] Salt, int Cycles = 50000)
        {
            using (var Deriver = new Rfc2898DeriveBytes(Password, Salt, Cycles))
            {
                return Deriver.GetBytes(NumberOfBytes);
            }
        }
    }
}
