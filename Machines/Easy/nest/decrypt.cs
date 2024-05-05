using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace Dec {
	class Decryptor {
		public static void Main() {
			var pt = Decrypt("yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4=", "667912", "1313Rf99", 3, "1L1SA61493DRV53Z", 256);
			Console.WriteLine("Plaintext: " + pt);
		}

		public static String Decrypt(String cipherText, String passPhrase, String saltValue, int passwordIterations, String initVector,int keySize) {
			var initVectorBytes = Encoding.ASCII.GetBytes(initVector);
			var saltValueBytes = Encoding.ASCII.GetBytes(saltValue);
			var cipherTextBytes = Convert.FromBase64String(cipherText);
			var password = new Rfc2898DeriveBytes(passPhrase, saltValueBytes, passwordIterations);
			var keyBytes = password.GetBytes(keySize / 8);
			var symmetricKey = new AesCryptoServiceProvider();
			symmetricKey.Mode = CipherMode.CBC;
			var decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes);
			var memoryStream = new MemoryStream(cipherTextBytes);
			var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
			var plainTextBytes = new byte[cipherTextBytes.Length];
			var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0,
			plainTextBytes.Length);
			memoryStream.Close();
			cryptoStream.Close();
			var plainText = Encoding.ASCII.GetString(plainTextBytes, 0, decryptedByteCount);
			return plainText;
		}
	}
}
