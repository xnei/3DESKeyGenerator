using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace _3DESKeyGenerator
{
    /// <summary>
    /// Generate 3DES components and combined key.
    /// </summary>
    class Program
    {
        const string finalMsg = "Press ESC to quit, or press ENTER to generate new Keys.";
        static void Main(string[] args)
        {
            Run();
            Console.WriteLine(finalMsg);

            ConsoleKey key;

            do
            {
                key = Console.ReadKey(true).Key;

                if (key == ConsoleKey.Escape)
                {
                    Environment.Exit(0);
                    break;                   
                }
                else if (key == ConsoleKey.Enter)
                {
                    Console.Clear();
                    Run();
                    Console.WriteLine(finalMsg);
                }

            } while (true);

            
        }


        public static void Run()
        {
            //generate the components
            var component1 = ByteArrayToString(GenerateThreeDesKey());
            var component2 = ByteArrayToString(GenerateThreeDesKey());
            var component3 = ByteArrayToString(GenerateThreeDesKey());

            //get the combined key
            var combinedKey = ByteArrayToString(Combine3DESComponents(
                HexStringToByteArray(component1),
                HexStringToByteArray(component2),
                HexStringToByteArray(component3)));


            //get the KCVs
            var component1KCV = GetKcv3Des(component1);
            var component2KCV = GetKcv3Des(component2);
            var component3KCV = GetKcv3Des(component3);
            var combinedKeyKCV = GetKcv3Des(combinedKey);


            //print the results!
            Console.WriteLine("\nGenerating keys...\n");

            Console.WriteLine($"\tComponent 1: {component1}     - KCV: {component1KCV}");
            Console.WriteLine($"\tComponent 2: {component2}     - KCV: {component2KCV}");
            Console.WriteLine($"\tComponent 3: {component3}     - KCV: {component3KCV}");


            Console.WriteLine($"\n\tCombined Key: {combinedKey}    - KCV: {combinedKeyKCV}");

            Console.WriteLine("\n\n\n\n\n\nThanks for using the 3DESKeyGenerator! Created by Xnei - 2021\n\n");
        }


        //generate a component
        public static byte[] GenerateThreeDesKey()
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] tripleDesKey = new byte[24]; //(will generate a 48 sized key)
            rng.GetBytes(tripleDesKey);
            for (var i = 0; i < tripleDesKey.Length; ++i)
            {
                int keyByte = tripleDesKey[i] & 0xFE;
                var parity = 0;
                for (int b = keyByte; b != 0; b >>= 1)
                    parity ^= b & 1;
                tripleDesKey[i] = (byte)(keyByte | (parity == 0 ? 1 : 0));
            }
            return tripleDesKey;
        }

        //combine the three components into a key!
        public static byte[] Combine3DESComponents(byte[] key1, byte[] key2, byte[] key3)
        {
            byte[] result = new byte[key1.Length];
            int i = 0;
            foreach (byte by1 in key1)
            {
                byte by2 = key2[i];
                byte by3 = key3[i];
                result[i] = (byte)(by1 ^ by2 ^ by3);
                i++;
            }
            return result;
        }

        //get the KCV (key check value)
        private static string GetKcv3Des(string key)
        {
            var iv = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            var data = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            TripleDES des = new TripleDESCryptoServiceProvider();

            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, des.CreateEncryptor(HexStringToByteArray(key), iv), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();
                    return ByteArrayToString(memoryStream.ToArray()).Remove(6);
                }
            }
        }




        #region converters

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString().ToUpper();
        }

        public static byte[] HexStringToByteArray(String hex)
        {
            if (hex.Substring(0, 2) == "0x")
                hex = hex.Substring(2);
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }


        #endregion




        //To check the KCVs
        //https://www.celersms.com/KCV.htm
        //https://fint-1227.appspot.com/descalc/

        //To check the combined key
        //https://emvlab.org/keyshares/
        //https://neapay.com/online-tools/hsm-keys-compose.html

    }



}
