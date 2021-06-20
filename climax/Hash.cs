using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace climax
{
    class Hash
    {
        private static readonly Random random = new Random();
        public static string Base64(string option, string plainText)
        {
            switch (option)
            {
                case "encode":
                    var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
                    return Convert.ToBase64String(plainTextBytes);
                case "decode":
                    var base64EncodedBytes = Convert.FromBase64String(plainText);
                    return Encoding.UTF8.GetString(base64EncodedBytes);
                default:
                    return "unknown";
            }
        }
        public static string MD5(string input)
        {
            // Use input string to calculate MD5 hash
            var md5 = System.Security.Cryptography.MD5.Create();
            var inputBytes = Encoding.ASCII.GetBytes(input);
            var hashBytes = md5.ComputeHash(inputBytes);

            // Convert the byte array to hexadecimal string
            var sb = new StringBuilder();
            foreach (var t in hashBytes)
            {
                sb.Append(t.ToString("x2"));
            }
            return sb.ToString();
        }
        
        public static string RandomString(int length)
        {
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        }
    }
}
