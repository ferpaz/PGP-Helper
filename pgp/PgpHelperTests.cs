using System.Text;

namespace Pgp;

[TestClass]
public class PgpHelperTests
{
    private readonly string _keyFolder;
    private readonly string _filesFolder;

    private const string PassCode = "FrasePeligrosa";

    private const string PublicKeyFilename = "0x6551A2EA-pub.asc";
    private const string PrivateKeyFilename = "0x6551A2EA-sec.asc";

    public PgpHelperTests()
    {
        _keyFolder = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..\\..\\..\\..\\PGP-key"));
        _filesFolder = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..\\..\\..\\..\\files"));
    }

    private string GetKeyPublicKeyFilename => Path.Combine(_keyFolder, PublicKeyFilename);

    private string GetKeyPrivateKeyFilename => Path.Combine(_keyFolder, PrivateKeyFilename);

    [TestInitialize]
    public void TestInitialize()
    {
        if (!File.Exists(GetKeyPublicKeyFilename))
            throw new FileNotFoundException(GetKeyPublicKeyFilename);

        if (!File.Exists(GetKeyPrivateKeyFilename))
            throw new FileNotFoundException(GetKeyPrivateKeyFilename);
    }


    [TestMethod]
    public void PgpEncryptDecryptAsciiString()
    {
        var input = Encoding.ASCII.GetBytes("test 1");

        // For encription we need the public key
        var publicKey = File.ReadAllBytes(GetKeyPublicKeyFilename);
        var encrBytes = PgpHelper.Encrypt(input, publicKey);

        // For decryption we need the private key
        var privateKey = File.OpenRead(GetKeyPrivateKeyFilename);
        var decrypted = PgpHelper.Decrypt(encrBytes, privateKey, PassCode);

        // Check the result
        Assert.AreEqual("test 1", Encoding.ASCII.GetString(decrypted));
    }

    [TestMethod]
    public void PgpEncryptDecryptTextFile()
    {
        // Open the file UTF8 Encoded to encrypt
        string testFilename = Path.Combine(_filesFolder, "test-utf8.txt");
        var input = File.ReadAllBytes(testFilename);

        // For encription we need the public key
        var publicKey = File.ReadAllBytes(GetKeyPublicKeyFilename);
        var encrBytes = PgpHelper.Encrypt(input, publicKey);

        // For decryption we need the private key
        var privateKey = File.OpenRead(GetKeyPrivateKeyFilename);
        var decrypted = PgpHelper.Decrypt(encrBytes, privateKey, PassCode);

        // Check the result
        Assert.IsNotNull(input);
        Assert.IsNotNull(decrypted);

        Assert.AreEqual(input.Length, decrypted.Length);

        Assert.AreEqual(Encoding.UTF8.GetString(input), Encoding.UTF8.GetString(decrypted));
    }
}