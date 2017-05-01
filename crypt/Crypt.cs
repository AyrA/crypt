//If you want to use this on linux, remove the #define statement
#define FASTHASH
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace crypt
{
    public struct CryptHeader
    {
        public string Header;
        public byte[] Salt, IV, KeyHash, FileHash;
        public bool Valid;

        public void ReadFrom(Stream S)
        {
            using (var BR = new BinaryReader(S, Encoding.UTF8, true))
            {
                Header = Encoding.UTF8.GetString(BR.ReadBytes(Crypt.HEADER.Length));
                Valid = Crypt.HEADER == Header;
                if (Valid)
                {
                    Salt = BR.ReadBytes(BR.ReadInt32());
                    KeyHash = BR.ReadBytes(BR.ReadInt32());
                    IV = BR.ReadBytes(BR.ReadInt32());
                    FileHash = BR.ReadBytes(BR.ReadInt32());
                }
            }
        }
        public void WriteTo(Stream S)
        {
            using (BinaryWriter BW = new BinaryWriter(S, Encoding.UTF8, true))
            {
                BW.Write(Encoding.UTF8.GetBytes(Header = Crypt.HEADER));
                BW.Write(Salt.Length);
                BW.Write(Salt);
                BW.Write(KeyHash.Length);
                BW.Write(KeyHash);
                BW.Write(IV.Length);
                BW.Write(IV);
                BW.Write(FileHash.Length);
                BW.Write(FileHash);
                BW.Flush();
            }
        }

        public int GetSize()
        {
            return Encoding.UTF8.GetByteCount(Header) +
                4 + Salt.Length +
                4 + IV.Length +
                4 + KeyHash.Length +
                4 + FileHash.Length;
        }
    }

    public class Crypt
    {
        [Flags]
        public enum CryptResult : int
        {
            /// <summary>
            /// Operation successful
            /// </summary>
            Success = 0,
            /// <summary>
            /// Generic error
            /// </summary>
            Error = 1,
            /// <summary>
            /// Source file was not found or is locked
            /// </summary>
            FileCantOpen = 2 | Error,
            /// <summary>
            /// Can't create destination file
            /// </summary>
            FileCantCreate = 4 | Error,
            /// <summary>
            /// Password is invalid.
            /// Either it's wrong for decryption or not supplied for encryption
            /// </summary>
            PasswordInvalid = 8 | Error,
            /// <summary>
            /// File hash did not verify
            /// </summary>
            FileHashInvalid = 16 | Error,
            /// <summary>
            /// File state is invalid. Reasons:
            /// - Attemting to decrypt unencrypted file
            /// - Encrypt already encrypted file.
            /// This error can be resolved by just copying/moving the file.
            /// </summary>
            InvalidFileState = 32 | Error,
            /// <summary>
            /// The cryptographic stream is damaged
            /// </summary>
            CryptoStreamError = 64 | Error,
            /// <summary>
            /// Generic error when reading or writing to file
            /// </summary>
            IOError = 128 | Error,
        }

#if FASTHASH
        /// <summary>
        /// Compares the first count characters of the objects pointed to by b1 and b2.
        /// The comparison is done lexicographically.
        /// </summary>
        /// <param name="b1">Region 1</param>
        /// <param name="b2">Region 2</param>
        /// <param name="count">Length of Region 1 or 2 (use lower of both numbers)</param>
        /// <returns>
        /// Negative value if b1 appears before b2 in lexicographical order.
        /// Zero if b1 and b2 compare equal, or if count is zero.
        /// Positive value if b1 appears after b2 in lexicographical order.</returns>
        /// <see cref="http://en.cppreference.com/w/c/string/byte/memcmp"/>
        /// <remarks>
        /// Needs the "FASTHASH" compiler directive defined to be present and used.
        /// Compare the lengths of the arrays and if either one is null. If they differ you don't need to call this function.
        /// The behavior is undefined if access occurs beyond the end of either object pointed to by b1 and b2.
        /// The behavior is undefined if either b1 or b2 is a null pointer.
        /// </remarks>
        [System.Runtime.InteropServices.DllImport("msvcrt.dll", CallingConvention = System.Runtime.InteropServices.CallingConvention.Cdecl)]
        private static extern int memcmp(byte[] b1, byte[] b2, long count);
#endif
        /// <summary>
        /// Hash algorithm to use. Do not change
        /// </summary>
        public const string HASHALG = "SHA256";
        /// <summary>
        /// Header value. Do not change
        /// </summary>
        public const string HEADER = "ACRYPT";

        public static byte[] Hash(Stream S)
        {
            using (var Hasher = (SHA256)HashAlgorithm.Create(HASHALG))
            {
                byte[] Hash = Hasher.ComputeHash(S);
                return Hash;
            }
        }

        /// <summary>
        /// Encrypts a file
        /// </summary>
        /// <param name="Filename">Source file</param>
        /// <param name="DestinationName">Encrypted destination</param>
        /// <param name="Password">User supplied password</param>
        /// <returns>true, if successfull</returns>
        /// <remarks>Will neither delete source on success nor destination on error</remarks>
        public static CryptResult EncryptFile(string Filename, string DestinationName, string Password)
        {
            if (string.IsNullOrEmpty(Password))
            {
                return CryptResult.PasswordInvalid;
            }
            var Header = GetHeader(Filename);
            //If the file is encrypted already you can just move it
            //We should probably check the password in the future however
            if (Header.Valid)
            {
                return CryptResult.InvalidFileState;
            }
            else
            {
                using (Rijndael R = Rijndael.Create())
                {
                    Header = new CryptHeader();
                    Header.Valid = true;
                    R.GenerateIV();
                    Header.IV = R.IV;
                    //Finds the largest keysize. This is in bits, not bytes so we divide by 8.
                    int KeySize = R.LegalKeySizes.OrderByDescending(m => m.MaxSize).First().MaxSize / 8;
                    //Randomly generate a salt for each encryption task.
                    //This makes the password different for each file even if the source file and password are identical.
                    Header.Salt = RandomBytes(KeySize);
                    //Get the key
                    byte[] Key = DeriveBytes(Password, KeySize, Header.Salt);
                    //Get Hash for password verification.
                    //This hash allows us to check if a user supplied the correct password for decryption.
                    //This should not be insecure as it still goes through the password generator and thus is very slow.
                    Header.KeyHash = GetPasswordByteHash(Key);
                    //Placeholder for the File hash. When decrypting, this is used to verify integrity.
                    Header.FileHash = new byte[256 / 8];
                    long HashPos = 0;
                    FileStream IN, FS;
                    CryptoStream CS;

                    try
                    {
                        IN = File.OpenRead(Filename);
                    }
                    catch
                    {
                        return CryptResult.FileCantOpen;
                    }

                    try
                    {
                        FS = File.Create(DestinationName);
                    }
                    catch
                    {
                        IN.Close();
                        IN.Dispose();
                        return CryptResult.FileCantCreate;
                    }

                    using (IN)
                    {
                        using (FS)
                        {
                            Header.WriteTo(FS);
                            HashPos = FS.Position - Header.FileHash.Length;

                            try
                            {
                                CS = new CryptoStream(FS, R.CreateEncryptor(Key, R.IV), CryptoStreamMode.Write);
                            }
                            catch
                            {
                                return CryptResult.CryptoStreamError;
                            }

                            using (CS)
                            {
                                using (var Hasher = (SHA256)HashAlgorithm.Create(HASHALG))
                                {
                                    int readed = 0;
                                    byte[] Buffer = new byte[R.BlockSize * 10];
                                    do
                                    {
                                        try
                                        {
                                            readed = IN.Read(Buffer, 0, Buffer.Length);
                                        }
                                        catch
                                        {
                                            return CryptResult.IOError;
                                        }
                                        if (readed > 0)
                                        {
                                            try
                                            {
                                                CS.Write(Buffer, 0, readed);
                                            }
                                            catch (IOException)
                                            {
                                                return CryptResult.IOError;
                                            }
                                            catch
                                            {
                                                return CryptResult.CryptoStreamError;
                                            }

                                            if (IN.Position == IN.Length)
                                            {
                                                var temp = Hasher.TransformFinalBlock(Buffer, 0, readed);
                                            }
                                            else
                                            {
                                                Hasher.TransformBlock(Buffer, 0, readed, Buffer, 0);
                                            }
                                        }
                                    } while (readed > 0);
                                    Header.FileHash = CreateHMAC(Key, (byte[])Hasher.Hash.Clone());
                                }
                                try
                                {
                                    CS.FlushFinalBlock();
                                }
                                catch (IOException)
                                {
                                    return CryptResult.IOError;
                                }
                                catch
                                {
                                    return CryptResult.CryptoStreamError;
                                }
                                //Store File hash and seek back to the end
                                try
                                {
                                    FS.Flush();
                                    FS.Seek(HashPos, SeekOrigin.Begin);
                                    FS.Write(Header.FileHash, 0, Header.FileHash.Length);
                                    FS.Flush();
                                    FS.Seek(0, SeekOrigin.End);
                                }
                                catch
                                {
                                    return CryptResult.IOError;
                                }
                            }
                        }
                    }
                }
            }
            return CryptResult.Success;
        }

        /// <summary>
        /// Decrypts a file
        /// </summary>
        /// <param name="Filename">Encrypted file</param>
        /// <param name="DestinationName">Decrypted file</param>
        /// <param name="Password">User supplied password</param>
        /// <returns>true, if successfull</returns>
        /// <remarks>Will neither delete source on success nor destination on error</remarks>
        public static CryptResult DecryptFile(string Filename, string DestinationName, string Password)
        {
            if (string.IsNullOrEmpty(Password))
            {
                return CryptResult.PasswordInvalid;
            }
            var Header = GetHeader(Filename);
            if (!Header.Valid)
            {
                return File.Exists(Filename) ? CryptResult.InvalidFileState : CryptResult.FileCantOpen;
            }
            using (Rijndael R = Rijndael.Create())
            {
                int KeySize = R.LegalKeySizes.OrderByDescending(m => m.MaxSize).First().MaxSize / 8;
                FileStream IN, FS;
                CryptoStream CS;

                try
                {
                    IN = File.OpenRead(Filename);
                    IN.Seek(Header.GetSize(), SeekOrigin.Begin);
                }
                catch
                {
                    return CryptResult.FileCantOpen;
                }

                try
                {
                    FS = File.Create(DestinationName);
                }
                catch
                {
                    IN.Close();
                    IN.Dispose();
                    return CryptResult.FileCantCreate;
                }

                using (IN)
                {
                    byte[] Key = DeriveBytes(Password, KeySize, Header.Salt);

                    if (!CheckPasswordBytes(Key, Header.KeyHash))
                    {
                        return CryptResult.PasswordInvalid;
                    }

                    using (FS)
                    {
                        try
                        {
                            CS = new CryptoStream(IN, R.CreateDecryptor(Key, Header.IV), CryptoStreamMode.Read);
                        }
                        catch
                        {
                            return CryptResult.CryptoStreamError;
                        }
                        using (CS)
                        {
                            using (var Hasher = (SHA256)HashAlgorithm.Create(HASHALG))
                            {
                                byte[] Data = new byte[R.BlockSize * 100];
                                int readed = 0;
                                do
                                {
                                    try
                                    {
                                        readed = CS.Read(Data, 0, Data.Length);
                                    }
                                    catch (IOException)
                                    {
                                        return CryptResult.IOError;
                                    }
                                    catch
                                    {
                                        return CryptResult.CryptoStreamError;
                                    }
                                    if (readed > 0)
                                    {
                                        try
                                        {
                                            FS.Write(Data, 0, readed);
                                        }
                                        catch
                                        {
                                            return CryptResult.IOError;
                                        }
                                        //Always read a multiple of the supported blocksize to avoid problems with readahead
                                        if (IN.Position == IN.Length)
                                        {
                                            Hasher.TransformFinalBlock(Data, 0, readed);
                                        }
                                        else
                                        {
                                            Hasher.TransformBlock(Data, 0, readed, Data, 0);
                                        }
                                    }
                                } while (readed > 0);
                                if (!VerifyHMAC(Key, Header.FileHash, Hasher.Hash))
                                {
                                    return CryptResult.FileHashInvalid;
                                }
                            }
                        }
                    }
                }
            }
            return CryptResult.Success;
        }

        /// <summary>
        /// Verifies a HMAC
        /// </summary>
        /// <param name="Salt">Salt to generate HMAC</param>
        /// <param name="OriginalHash">Hash on record</param>
        /// <param name="NewHash">New Hash to generate HMAC and check</param>
        /// <returns>True, if identical</returns>
        private static bool VerifyHMAC(byte[] Salt, byte[] OriginalHash, byte[] NewHash)
        {
            return CompareBytes(CreateHMAC(Salt, NewHash), OriginalHash);
        }

        /// <summary>
        /// Creates a HMAC (SHA256)
        /// </summary>
        /// <param name="Salt">Salt</param>
        /// <param name="Content">Content to create HMAC from</param>
        /// <returns>HMAC</returns>
        private static byte[] CreateHMAC(byte[] Salt, byte[] Content)
        {
            using (HMACSHA256 H = new HMACSHA256(Salt))
            {
                return H.ComputeHash(Content);
            }
        }

        /// <summary>
        /// Creates the <see cref="HASHALG"/> Hash of a password
        /// </summary>
        /// <param name="Password">Password (or other binary content)</param>
        /// <returns>Hash</returns>
        private static byte[] GetPasswordByteHash(byte[] Password)
        {
            using (var A = HashAlgorithm.Create(HASHALG))
            {
                return A.ComputeHash(Password);
            }
        }

        /// <summary>
        /// Checks an existing password hash against a password or other binary content
        /// </summary>
        /// <param name="Password">Password</param>
        /// <param name="Hash">Hash</param>
        /// <returns>true, if identical</returns>
        private static bool CheckPasswordBytes(byte[] Password, byte[] Hash)
        {
            return CompareBytes(GetPasswordByteHash(Password), Hash);
        }

        /// <summary>
        /// Compares two byte arrays
        /// </summary>
        /// <param name="B1">Array 1</param>
        /// <param name="B2">Array 2</param>
        /// <returns>true, if identical</returns>
        private static bool CompareBytes(byte[] B1, byte[] B2)
        {
            if (B1 == null && B2 == null)
            {
                return true;
            }
#if FASTHASH
            return B1 != null && B2 != null && B1.Length == B2.Length && memcmp(B1, B2, B1.Length) == 0;
#else
            if (B1 == null || B2 == null || B1.Length != B2.Length)
            {
                return false;
            }

            for (var i = 0; i < B1.Length; i++)
            {
                if (B1[i] != B2[i])
                {
                    return false;
                }
            }
            return true;
#endif
        }

        /// <summary>
        /// Tries to read the crypt header from a file
        /// </summary>
        /// <param name="Filename">File name</param>
        /// <returns>Crypt header. Check the valid property before using any of its values</returns>
        public static CryptHeader GetHeader(string Filename)
        {
            try
            {
                using (var FS = File.OpenRead(Filename))
                {
                    var H = new CryptHeader();
                    H.ReadFrom(FS);
                    return H;
                }
            }
            catch
            {
                return new CryptHeader();
            }
        }

        /// <summary>
        /// Checks if a file has a crypt header
        /// </summary>
        /// <param name="Filename">File name</param>
        /// <returns>true, if it has valid header</returns>
        /// <remarks>This will not attempt to verify the header or content itself</remarks>
        public static bool IsEncrypted(string Filename)
        {
            return GetHeader(Filename).Valid;
        }

        /// <summary>
        /// Generates cryptographically safe random bytes
        /// </summary>
        /// <param name="Count">Number of bytes to generate</param>
        /// <returns>Byte array</returns>
        private static byte[] RandomBytes(int Count)
        {
            byte[] Data = new byte[Count];
            using (RNGCryptoServiceProvider RNG = (RNGCryptoServiceProvider)RandomNumberGenerator.Create())
            {
                RNG.GetBytes(Data);
            }
            return Data;
        }

        /// <summary>
        /// Derives the encryption/decryption bytes from a string
        /// </summary>
        /// <param name="Password">User supplied password</param>
        /// <param name="NumberOfBytes">Number of bytes needed</param>
        /// <param name="Salt">Salt. This should be unique to each file</param>
        /// <param name="Cycles">Cycles for the function. Bigger takes longer.</param>
        /// <returns>Pseudorandom bytes</returns>
        /// <remarks>crypt does not stores the cycles in the header. You need to remember for yourself.</remarks>
        private static byte[] DeriveBytes(string Password, int NumberOfBytes, byte[] Salt, int Cycles = 50000)
        {
            using (var Deriver = new Rfc2898DeriveBytes(Password, Salt, Cycles))
            {
                return Deriver.GetBytes(NumberOfBytes);
            }
        }
    }
}
