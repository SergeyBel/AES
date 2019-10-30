using System;
using System.Linq;

namespace SandBoxConsole
{
    class Program
    {
        private static byte[] plain = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; //plaintext example
        private static byte[] key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; //key example
        private static byte[] iv = plain.Reverse().ToArray();

        static void Main(string[] args)
        {
            TestECB();
            TestCBC();
            TestCfB();

            Console.ReadKey();
        }

        static void TestECB()
        {
            AES aes = new AES(128);

            Console.WriteLine("--------------------------- ECB ---------------------------");

            var e = aes.EncryptECB(plain, key);
            Console.Write("Encrypted: ");
            aes.printHexArray(e);

            var d = aes.DecryptECB(e, key);
            Console.Write("Decrypted: ");
            aes.printHexArray(d);

            Console.Write("Plain:     ");
            aes.printHexArray(plain);

            Console.WriteLine("-----------------------------------------------------------");
        }

        static void TestCBC()
        {
            AES aes = new AES(128);

            Console.WriteLine("--------------------------- CBC ---------------------------");

            var e = aes.EncryptCBC(plain, key, iv);
            Console.Write("Encrypted: ");
            aes.printHexArray(e);

            var d = aes.DecryptCBC(e, key, iv);
            Console.Write("Decrypted: ");
            aes.printHexArray(d);

            Console.Write("Plain:     ");
            aes.printHexArray(plain);

            Console.WriteLine("-----------------------------------------------------------");
        }

        static void TestCfB()
        {
            AES aes = new AES(128);

            Console.WriteLine("--------------------------- CFB ---------------------------");

            var e = aes.EncryptCFB(plain, key, iv);
            Console.Write("Encrypted: ");
            aes.printHexArray(e);

            var d = aes.DecryptCFB(e, key, iv);
            Console.Write("Decrypted: ");
            aes.printHexArray(d);

            Console.Write("Plain:     ");
            aes.printHexArray(plain);

            Console.WriteLine("-----------------------------------------------------------");
        }
    }
}
