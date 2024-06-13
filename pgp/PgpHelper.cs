using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;

namespace Pgp
{
    public static class PgpHelper
    {
        /// <summary>
        /// A simple routine that opens a key ring file and loads the first available key suitable for encryption.
        /// </summary>
        /// <param name="inputStream">The stream to read the secret key from.</param>
        /// <returns>The first PgpPublicKey found.</returns>
        public static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);
            
            PgpPublicKeyRingBundle pgpPub = new(inputStream);
            
            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //
            //
            // iterate through the key rings.
            //
            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey k in kRing.GetPublicKeys())
                {
                    if (k.IsEncryptionKey)
                        return k;
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        /// <summary>
        /// Search a secret key ring collection for a secret key corresponding to keyId if it exists.
        /// </summary>
        /// <param name="pgpSec">a secret key ring collection</param>
        /// <param name="keyId">keyId we want</param>
        /// <param name="pass">passphrase to decrypt secret key with</param>
        private static PgpPrivateKey? FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);
            if (pgpSecKey == null)
                return null;

            return pgpSecKey.ExtractPrivateKey(pass);
        }

        /// <summary>
        /// Decrypt the byte array passed into inputData and return it as another byte array.
        /// </summary>
        /// <param name="inputData">the data to decrypt</param>
        /// <param name="keyId">a stream from your private keyring file</param>
        /// <param name="pass">the password</param>
        /// <returns>decrypted data as byte array</returns>
        public static byte[] Decrypt(byte[] inputData, Stream keyIn, string passCode)
        {
            byte[] error = Encoding.ASCII.GetBytes("ERROR");

            Stream inputStream = new MemoryStream(inputData);
            inputStream = PgpUtilities.GetDecoderStream(inputStream);
            MemoryStream decoded = new();

            try
            {
                PgpObjectFactory pgpF = new(inputStream);
                PgpEncryptedDataList enc;
                PgpObject o = pgpF.NextPgpObject();

                //
                // the first object might be a PGP marker packet.
                //
                enc = o is PgpEncryptedDataList list
                    ? list
                    : (PgpEncryptedDataList)pgpF.NextPgpObject();

                //
                // find the secret key
                //
                PgpPrivateKey? sKey = null;
                PgpPublicKeyEncryptedData? pbe = null;
                PgpSecretKeyRingBundle pgpSec = new(
                PgpUtilities.GetDecoderStream(keyIn));
                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {
                    sKey = FindSecretKey(pgpSec, pked.KeyId, passCode.ToCharArray());
                    if (sKey != null)
                    {
                        pbe = pked;
                        break;
                    }
                }
                if (sKey == null)
                    throw new ArgumentException("secret key for message not found.");

                using (Stream clear = pbe!.GetDataStream(sKey))
                {
                    PgpObjectFactory plainFact = new(clear);
                    PgpObject message = plainFact.NextPgpObject();

                    if (message is PgpCompressedData cData)
                    {
                        PgpObjectFactory pgpFact = new(cData.GetDataStream());
                        message = pgpFact.NextPgpObject();
                    }

                    if (message is PgpLiteralData ld)
                    {
                        Stream unc = ld.GetInputStream();
                        PipeAll(unc, decoded);
                    }
                    else if (message is PgpOnePassSignatureList)
                        throw new PgpException("encrypted message contains a signed message - not literal data.");
                    else
                        throw new PgpException("message is not a simple encrypted file - type unknown.");
                }

                if (pbe.IsIntegrityProtected() && !pbe.Verify())
                    throw new InvalidOperationException("Message failed integrity check.");

                return decoded.ToArray();
            }
            catch (Exception e)
            {
                if (e.Message.StartsWith("Checksum mismatch"))
                    throw new InvalidOperationException("Invalid Passcode - Likely invalid passcode. Possible data corruption.", e);
                else if (e.Message.StartsWith("Object reference not"))
                    throw new InvalidOperationException("PGP data does not exist.", e);
                else if (e.Message.StartsWith("Premature end of stream"))
                    throw new InvalidOperationException("Partial PGP data found.", e);
                else
                    throw;
            }
        }

        /// <summary>
        /// Encrypt the data.
        /// </summary>
        /// <param name="inputData">a secret key ring collection</param>
        /// <param name="passPhrase">the password returned by "ReadPublicKey"</param>
        /// <param name="withIntegrityCheck">check the data for errors</param>
        /// <param name="armor">protect the data streams</param>
        /// <returns>encrypted data as byte array</returns>
        public static byte[] Encrypt(byte[] inputData, PgpPublicKey passPhrase, bool withIntegrityCheck, bool armor)
        {
            byte[] processedData = Compress(inputData, PgpLiteralData.Console, CompressionAlgorithmTag.Uncompressed);

            MemoryStream bOut = new();
            Stream output = bOut;

            if (armor)
                output = new ArmoredOutputStream(output);

            PgpEncryptedDataGenerator encGen = new(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());
            encGen.AddMethod(passPhrase);

            Stream encOut = encGen.Open(output, processedData.Length);

            encOut.Write(processedData, 0, processedData.Length);
            encOut.Close();

            if (armor)
                output.Close();

            return bOut.ToArray();
        }

        /// <summary>
        /// Encrypt the data.
        /// </summary>
        /// <param name="inputData">a secret key ring collection</param>
        /// <param name="publicKey">the public key</param>
        /// <returns>encrypted data as byte array</returns>
        public static byte[] Encrypt(byte[] inputData, byte[] publicKey)
        {
            Stream publicKeyStream = new MemoryStream(publicKey);

            PgpPublicKey encKey = ReadPublicKey(publicKeyStream);

            return Encrypt(inputData, encKey, true, true);
        }

        private static byte[] Compress(byte[] clearData, string fileName, CompressionAlgorithmTag algorithm)
        {
            MemoryStream bOut = new();

            PgpCompressedDataGenerator comData = new(algorithm);
            Stream cos = comData.Open(bOut); // open it with the final destination
            PgpLiteralDataGenerator lData = new();

            // we want to Generate compressed data. This might be a user option later,
            // in which case we would pass in bOut.
            Stream pOut = lData.Open(
            cos,                    // the compressed output stream
            PgpLiteralData.Binary,
            fileName,               // "filename" to store
            clearData.Length,       // length of clear data
            DateTime.UtcNow         // current time
            );

            pOut.Write(clearData, 0, clearData.Length);
            pOut.Close();

            comData.Close();

            return bOut.ToArray();
        }

        private const int _bufferSize = 512;

        public static void PipeAll(Stream inStr, Stream outStr)
        {
            byte[] bs = new byte[_bufferSize];
            int numRead;
            while ((numRead = inStr.Read(bs, 0, bs.Length)) > 0)
            {
                outStr.Write(bs, 0, numRead);
            }
        }
    }
}
