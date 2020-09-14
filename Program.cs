using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System;
using System.IO;
using System.Linq;
using System.Security;

namespace Jeto.PdfDecryptor
{
    abstract class Program
    {
        static void Main(string[] args)
        {
            var pemText = File.ReadAllText("private.pem");
            var bytes = File.ReadAllBytes("test.out");
            
            var keyPair = DecodePrivateKey(pemText, "1234");

            var parser = new CmsEnvelopedDataParser(bytes);
            var recipients = parser.GetRecipientInfos().GetRecipients().OfType<RecipientInformation>();
            var recipientInformation = recipients.First();
            var decryptedStream = recipientInformation.GetContentStream(keyPair.Private).ContentStream;

            var pdfData = Convert.ToBase64String(ReadFully(decryptedStream));
            
            Console.WriteLine(pdfData);
            Console.ReadLine();
        }

        private static byte[] ReadFully(Stream input)
        {
            var buffer = new byte[16 * 1024];
            using (var ms = new MemoryStream())
            {
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ms.Write(buffer, 0, read);
                }
                return ms.ToArray();
            }
        }

        private static AsymmetricCipherKeyPair DecodePrivateKey(string encryptedPrivateKey, string password)
        {
            TextReader textReader = new StringReader(encryptedPrivateKey);
            var pemReader = new PemReader(textReader, new PasswordFinder(password));
            var privateKeyObject = pemReader.ReadObject();
            var rsaPrivateKey = (RsaPrivateCrtKeyParameters)privateKeyObject;
            var rsaPublicKey = new RsaKeyParameters(false, rsaPrivateKey.Modulus, rsaPrivateKey.PublicExponent);
            var kp = new AsymmetricCipherKeyPair(rsaPublicKey, rsaPrivateKey);
            return kp;
        }
    }

    public class PasswordFinder : IPasswordFinder
    {
        private readonly string _password;

        public PasswordFinder(string password)
        {
            _password = password;
        }


        public char[] GetPassword()
        {
            return _password.ToCharArray();
        }
    }

}
