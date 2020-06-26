using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Coderz.Kubernetes.Extensions
{
    /// <summary>
    /// Loads an X509Certificate2 from a Kubernetes TLS secret mapped as environment variables or as a file
    /// </summary>
    public static class TlsSecret
    {
        private const string OidRsa = "1.2.840.113549.1.1.1";
        private const string OidEcc = "1.2.840.10045.2.1";

        public static X509Certificate2Collection FromEnvironment(string certVar="tls_crt", string keyVar="tls_key")
        {
            string tlsCertData = Environment.GetEnvironmentVariable(certVar);
            string tlsKeyData = Environment.GetEnvironmentVariable(keyVar);

            return FromPemStrings(tlsCertData, tlsKeyData);
        }

        public static X509Certificate2Collection FromMappedPath(string path)
        {
            if (!Directory.Exists(path))
                return null;

            var dir = new DirectoryInfo(path);
            FileInfo tlsCertFile = dir.GetFiles("tls.crt").FirstOrDefault();
            FileInfo tlsKeyFile = dir.GetFiles("tls.key").FirstOrDefault();

            if (tlsCertFile == null) return null;
            string tlsCertData = File.ReadAllText(tlsCertFile.FullName);

            string tlsKeyData = (tlsKeyFile != null)
                ? File.ReadAllText(tlsKeyFile.FullName)
                : null;

            return FromPemStrings(tlsCertData, tlsKeyData);
        }

        public static X509Certificate2Collection FromPemStrings(string publicCertChain, string privateKey)
        {
            // initialize return collection
            var collection = new X509Certificate2Collection();

            // get public cert chain
            string[] certChainParts = publicCertChain.Split('-', StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < certChainParts.Length; i++)
            {
                if ((certChainParts[i] == "BEGIN CERTIFICATE") && (i < (certChainParts.Length - 1)))
                {
                    byte[] certBuffer = Convert.FromBase64String(certChainParts[++i]);
                    collection.Import(certBuffer);
                }
            }

            // replace certificate 0 to include private key
            if (! string.IsNullOrWhiteSpace(privateKey))
            {
                X509Certificate2 cert0 = collection[0];
                if (cert0.PublicKey.Oid.Value == OidRsa)
                    collection[0] = SetRsaPrivateKey(cert0, privateKey);
                else if (cert0.PublicKey.Oid.Value == OidEcc)
                    collection[0] = SetEcDsaPrivateKey(cert0, privateKey);
                else
                    throw new ArgumentException("Invalid Certificate Type for Private Key", nameof(privateKey));
            }

            return collection;
        }

        private static X509Certificate2 SetRsaPrivateKey(X509Certificate2 cert, string privateKey)
        {
            string[] keyParts = privateKey.Split('-', StringSplitOptions.RemoveEmptyEntries);
            byte[] keyBytes = Convert.FromBase64String(keyParts[1]);

            RSA rsaPrivateKey = RSA.Create();
            switch (keyParts[0])
            {
                case "BEGIN PRIVATE KEY":
                    rsaPrivateKey.ImportPkcs8PrivateKey(keyBytes, out _);
                    break;
                case "BEGIN RSA PRIVATE KEY":
                    rsaPrivateKey.ImportRSAPrivateKey(keyBytes, out _);
                    break;
                default:
                    throw new ArgumentException("Invalid PrivateKey String", nameof(privateKey));
            }

            return cert.CopyWithPrivateKey(rsaPrivateKey);
        }

        private static X509Certificate2 SetEcDsaPrivateKey(X509Certificate2 cert, string privateKey)
        {
            string[] keyParts = privateKey.Split('-', StringSplitOptions.RemoveEmptyEntries);
            byte[] keyBytes = Convert.FromBase64String(keyParts[1]);

            ECDsa eccPrivateKey = ECDsa.Create();
            if (eccPrivateKey == null) 
                throw new PlatformNotSupportedException("Unable to create ECDsa");

            switch (keyParts[0])
            {
                case "BEGIN PRIVATE KEY":
                    eccPrivateKey.ImportPkcs8PrivateKey(keyBytes, out _);
                    break;
                case "BEGIN EC PRIVATE KEY":
                    eccPrivateKey.ImportECPrivateKey(keyBytes, out _);
                    break;
                default:
                    throw new ArgumentException("Invalid PrivateKey String", nameof(privateKey));
            }

            return cert.CopyWithPrivateKey(eccPrivateKey);
        }
    }
}
