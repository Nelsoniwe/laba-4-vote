using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace laba4_vote.Models
{
    public class Person
    {
        public byte[] bulletin { get; set; }
        private byte[] randomStringData;
        private readonly RSACryptoServiceProvider rsaKey;
        private readonly RSACryptoServiceProvider rsaLargeKey;
        bool stringsRemoved = false;

        public List<byte[]> recievedBulletins { get; set; }
        public List<byte[]> Signs { get; set; }
        public List<byte[]> recievedSigns { get; set; }
        private string bulletinRandomString;
        private ElGamal elGamal;
        private ElGamalManaged privateSignKey;
        public ElGamalManaged PublicSignKey;

        public Person(int keySize, int keyLargeSize)
        {
            rsaKey = new RSACryptoServiceProvider(keySize);
            rsaLargeKey = new RSACryptoServiceProvider(keyLargeSize );
            randomStringData = Encoding.UTF8.GetBytes(RandomString());
            recievedBulletins = new List<byte[]>();
            Signs = new List<byte[]>();
            recievedSigns = new List<byte[]>();

            elGamal = new ElGamalManaged();
            elGamal.KeySize = 384;
            ((ElGamalManaged)elGamal).CreateKeyPair(elGamal.KeySize);

            privateSignKey = (ElGamalManaged)elGamal;

            PublicSignKey = (ElGamalManaged)elGamal;
            PublicSignKey.o_key_struct.X = 0;
        }

        public static string RandomString(int length = 8)
        {
            Random random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }
        public void CreateBulletin(string bulletin)
        {
            bulletinRandomString = RandomString();
            bulletin = (bulletin + bulletinRandomString);
            this.bulletin = Encoding.UTF8.GetBytes(bulletin);
        }

        public byte[] GenerateRandomString(byte[] input)
        {
            byte[] resultArray = new byte[input.Length + randomStringData.Length];
            input.CopyTo(resultArray, 0);
            randomStringData.CopyTo(resultArray, input.Length);

            return resultArray;
        }

        public void CheckBulletins()
        {
            bool result = false;

            foreach (var item in recievedBulletins)
            {
                if (isSubArray(item, randomStringData))
                {
                    result = true;
                }
            }

            if (!result && !stringsRemoved)
                Console.WriteLine("One of the voters can't find the bulletin");
        }

        public void RemoveStrings()
        {
            for (int i = 0; i < recievedBulletins.Count; i++)
            {
                recievedBulletins[i] = RemoveRandomString(recievedBulletins[i]);
            }
            stringsRemoved = true;
        }

        private byte[] RemoveRandomString(byte[] bytes)
        {
            if (isSubArray(bytes, randomStringData))
            {
                byte[] temp = new byte[bytes.Length - 8];
                for (int j = 0; j < temp.Length; j++)
                {
                    temp[j] = bytes[j];
                }
                return temp;
            }

            return null;
        }

        public void RecieveBulletin(byte[] bulletin)
        {
            recievedBulletins.Add(bulletin);
        }

        public byte[] Encrypt(byte[] data)
        {
            return rsaKey.Encrypt(data, false);
        }

        public byte[] EncryptLarge(byte[] data)
        {
            return rsaLargeKey.Encrypt(data, false);
        }

        public byte[] Decrypt(byte[] data)
        {
            return rsaKey.Decrypt(data, false);
        }

        public byte[] DecryptLarge(byte[] data)
        {
            return rsaLargeKey.Decrypt(data, false);
        }

        public void DecryptAll()
        {
            for (int i = 0; i < recievedBulletins.Count; i++)
            {
                recievedBulletins[i] = Decrypt(recievedBulletins[i]);
            }
        }

        public void SignBulletins()
        {
            for (int i = 0; i < recievedBulletins.Count; i++)
            {
                Signs.Add(CreateSignWithElGamal(recievedBulletins[i]));
            }
        }

        public void VerifySigns(ElGamalManaged publicSignKey)
        {
            for (int i = 0; i < recievedSigns.Count; i++)
            {
                bool resultOfCheck = publicSignKey.Verify(recievedBulletins[i], recievedSigns[i]);

                if (!resultOfCheck)
                {
                    Console.WriteLine("Bulletin sign is wrong");
                }
            }
        }

        private byte[] CreateSignWithElGamal(byte[] bytes)
        {
            SHA256 sha256 = SHA256.Create();
            byte[] hashText = sha256.ComputeHash(bytes);

            byte[] signature = elGamal.Sign(hashText);

            return signature;
        }

        public void DecryptAllLarge()
        {
            for (int i = 0; i < recievedBulletins.Count; i++)
            {
                recievedBulletins[i] = DecryptLarge(recievedBulletins[i]);
            }
        }

        public static bool isSubArray(byte[] arrayToCheck, byte[] subArray)
        {
            int n = arrayToCheck.Length;
            int m = subArray.Length;
            int i = 0, j = 0;

            while (i < n && j < m)
            {
                if (arrayToCheck[i] == subArray[j])
                {
                    i++;
                    j++;
                    if (j == m)
                        return true;
                }
                else
                {
                    i = i - j + 1;
                    j = 0;
                }
            }
            return false;
        }
    }
}