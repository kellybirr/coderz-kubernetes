using System.IO;
using System.Linq;

// ReSharper disable once CheckNamespace
namespace System.Security.Cryptography.X509Certificates
{
    /// <summary>
    /// Loads an X509Certificate2 from a Kubernetes TLS secret mapped as environment variables or as a file
    /// </summary>
    public static class X509CertificateExtensions
    {
        private const string OidRsa = "1.2.840.113549.1.1.1";
        private const string OidEcc = "1.2.840.10045.2.1";

        public static void AddToTrustStores(this X509Certificate2Collection collection, StoreLocation storeLocation)
        {
            using X509Store myCertStore = new X509Store(StoreName.My, storeLocation, OpenFlags.ReadWrite);
            using X509Store authCertStore = new X509Store(StoreName.CertificateAuthority, storeLocation, OpenFlags.ReadWrite);
            using X509Store rootCertStore = new X509Store(StoreName.Root, storeLocation, OpenFlags.ReadWrite);

            foreach (X509Certificate2 cert in collection)
            {
                if (myCertStore.Certificates.Contains(cert)) continue;
                if (authCertStore.Certificates.Contains(cert)) continue;
                if (rootCertStore.Certificates.Contains(cert)) continue;

                if (cert.HasPrivateKey)
                    myCertStore.Add(cert);
                else if (cert.Issuer == cert.Subject)
                    rootCertStore.Add(cert);
                else
                    authCertStore.Add(cert);
            }
        }

        public static X509Certificate2 ImportFromEnvironment(this X509Certificate2Collection collection, string certVar="tls_crt", string keyVar="tls_key")
        {
            string tlsCertData = Environment.GetEnvironmentVariable(certVar);
            string tlsKeyData = Environment.GetEnvironmentVariable(keyVar);

            return ImportPemStrings(collection, tlsCertData, tlsKeyData);
        }

        public static X509Certificate2 ImportTlsSecret(this X509Certificate2Collection collection, string mappedPath)
        {
            if (!Directory.Exists(mappedPath))
                return null;

            var dir = new DirectoryInfo(mappedPath);
            FileInfo tlsCertFile = dir.GetFiles("tls.crt").FirstOrDefault();
            FileInfo tlsKeyFile = dir.GetFiles("tls.key").FirstOrDefault();

            if (tlsCertFile == null) return null;
            string tlsCertData = File.ReadAllText(tlsCertFile.FullName);

            string tlsKeyData = (tlsKeyFile != null)
                ? File.ReadAllText(tlsKeyFile.FullName)
                : null;

            return ImportPemStrings(collection, tlsCertData, tlsKeyData);
        }

        public static void ImportCaSecret(this X509Certificate2Collection collection, string mappedPath)
        {
            if (!Directory.Exists(mappedPath))
                return;

            var dir = new DirectoryInfo(mappedPath);
            FileInfo caCertFile = dir.GetFiles("ca.crt").FirstOrDefault();

            if (caCertFile == null) return;
            string caCertData = File.ReadAllText(caCertFile.FullName);

            ImportPemStrings(collection, caCertData);
        }

        public static X509Certificate2 ImportPemStrings(this X509Certificate2Collection collection, string publicCertChain, string privateKey=null)
        {
            // get public cert chain
            X509Certificate2 privateKeyCert = null;
            string[] certChainParts = publicCertChain.Split('-', StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < certChainParts.Length; i++)
            {
                if ((certChainParts[i] == "BEGIN CERTIFICATE") && (i < (certChainParts.Length - 1)))
                {
                    // decode certificate from base64 in next string
                    byte[] certBuffer = Convert.FromBase64String(certChainParts[++i]);
                    var cert = new X509Certificate2(certBuffer);

                    // check if we need to add private key, if the first cert in the PEM
                    if (privateKeyCert == null && !string.IsNullOrWhiteSpace(privateKey))
                    {
                        privateKeyCert = cert.PublicKey.Oid.Value switch
                        {
                            OidRsa => SetRsaPrivateKey(cert, privateKey),
                            OidEcc => SetEcDsaPrivateKey(cert, privateKey),
                            _ => throw new ArgumentException("Invalid Certificate Type for Private Key", nameof(privateKey))
                        };

                        cert.Dispose(); // dispose old instance
                        cert = privateKeyCert;
                    }

                    collection.Add(cert);
                }
            }

            return privateKeyCert;
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
