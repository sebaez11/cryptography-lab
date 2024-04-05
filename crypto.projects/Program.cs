using System;
using System.IO;
using System.Security.Cryptography;

class Program
{
    static void Main()
    {
        string keysPath = "KEYS";
        Directory.CreateDirectory(keysPath);

        while (true)
        {
            Console.WriteLine("Selecciona una opción:");
            Console.WriteLine("1. Generar par de claves");
            Console.WriteLine("2. Firmar mensaje");
            Console.WriteLine("3. Verificar firma");
            Console.WriteLine("4. Salir");
            string option = Console.ReadLine();

            switch (option)
            {
                case "1":
                    GenerateKeyPair(keysPath);
                    break;
                case "2":
                    SignMessage(keysPath);
                    break;
                case "3":
                    VerifySignature(keysPath);
                    break;
                case "4":
                    return;
                default:
                    Console.WriteLine("Opción no válida.");
                    break;
            }
        }
    }

    static void GenerateKeyPair(string keysPath)
    {
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            RSAParameters privateKey = rsa.ExportParameters(true);
            RSAParameters publicKey = rsa.ExportParameters(false);

            string keyFolder = Path.Combine(keysPath, Guid.NewGuid().ToString());
            Directory.CreateDirectory(keyFolder);

            File.WriteAllText(Path.Combine(keyFolder, "publicKey.xml"), ToXmlString(publicKey));
            File.WriteAllText(Path.Combine(keyFolder, "privateKey.xml"), ToXmlString(privateKey));

            Console.WriteLine($"Claves generadas y guardadas en: {keyFolder}");
        }
    }

    static void SignMessage(string keysPath)
    {
        Console.WriteLine("Ingrese el mensaje a firmar:");
        string message = Console.ReadLine();
        File.WriteAllText("message.txt", message);

        Console.WriteLine("Ingrese la ruta de la clave privada:");
        string privateKeyPath = Console.ReadLine();

        try
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            string privateKeyXml = File.ReadAllText(privateKeyPath);
            rsa.FromXmlString(privateKeyXml);

            byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(message);
            byte[] signature = rsa.SignData(messageBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            File.WriteAllBytes("signature.txt", signature);
            Console.WriteLine("Mensaje firmado. Firma guardada en 'signature.txt'");
        }
        catch (Exception e)
        {
            Console.WriteLine($"Error: {e.Message}");
        }
    }

    static void VerifySignature(string keysPath)
    {
        string message = File.ReadAllText("message.txt");
        Console.WriteLine($"Mensaje a verificar: {message}");

        Console.WriteLine("Ingrese la ruta de la clave pública:");
        string publicKeyPath = Console.ReadLine();

        try
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            string publicKeyXml = File.ReadAllText(publicKeyPath);
            rsa.FromXmlString(publicKeyXml);

            byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(message);
            byte[] signature = File.ReadAllBytes("signature.txt");
            bool verified = rsa.VerifyData(messageBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            if (verified)
                Console.WriteLine("La firma es válida.");
            else
                Console.WriteLine("La firma es inválida.");
        }
        catch (Exception e)
        {
            Console.WriteLine($"Error: {e.Message}");
        }
    }

    static string ToXmlString(RSAParameters rsaParameters)
    {
        using (var sw = new StringWriter())
        {
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, rsaParameters);
            return sw.ToString();
        }
    }
}
