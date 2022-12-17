using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using laba4_vote.Models;

namespace laba4_vote
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Person personA = new Person(2048, 4096);
            Person personB = new Person(1536, 3584);
            Person personC = new Person(1024, 3072);
            Person personD = new Person(512, 2560);

            personA.CreateBulletin("1");
            personA.bulletin = personD.Encrypt(personA.bulletin);
            personA.bulletin = personC.Encrypt(personA.bulletin);
            personA.bulletin = personB.Encrypt(personA.bulletin);
            personA.bulletin = personA.Encrypt(personA.bulletin);

            personA.bulletin = personD.EncryptLarge(personD.GenerateRandomString(personA.bulletin));
            personA.bulletin = personC.EncryptLarge(personC.GenerateRandomString(personA.bulletin));
            personA.bulletin = personB.EncryptLarge(personB.GenerateRandomString(personA.bulletin));
            personA.bulletin = personA.EncryptLarge(personA.GenerateRandomString(personA.bulletin));

            personB.CreateBulletin("4");
            personB.bulletin = personD.Encrypt(personB.bulletin);
            personB.bulletin = personC.Encrypt(personB.bulletin);
            personB.bulletin = personB.Encrypt(personB.bulletin);
            personB.bulletin = personA.Encrypt(personB.bulletin);

            personB.bulletin = personD.EncryptLarge(personD.GenerateRandomString(personB.bulletin));
            personB.bulletin = personC.EncryptLarge(personC.GenerateRandomString(personB.bulletin));
            personB.bulletin = personB.EncryptLarge(personB.GenerateRandomString(personB.bulletin));
            personB.bulletin = personA.EncryptLarge(personA.GenerateRandomString(personB.bulletin));

            personC.CreateBulletin("2");
            personC.bulletin = personD.Encrypt(personC.bulletin);
            personC.bulletin = personC.Encrypt(personC.bulletin);
            personC.bulletin = personB.Encrypt(personC.bulletin);
            personC.bulletin = personA.Encrypt(personC.bulletin);

            personC.bulletin = personD.EncryptLarge(personD.GenerateRandomString(personC.bulletin));
            personC.bulletin = personC.EncryptLarge(personC.GenerateRandomString(personC.bulletin));
            personC.bulletin = personB.EncryptLarge(personB.GenerateRandomString(personC.bulletin));
            personC.bulletin = personA.EncryptLarge(personA.GenerateRandomString(personC.bulletin));

            personD.CreateBulletin("4");
            personD.bulletin = personD.Encrypt(personD.bulletin);
            personD.bulletin = personC.Encrypt(personD.bulletin);
            personD.bulletin = personB.Encrypt(personD.bulletin);
            personD.bulletin = personA.Encrypt(personD.bulletin);

            personD.bulletin = personD.EncryptLarge(personD.GenerateRandomString(personD.bulletin));
            personD.bulletin = personC.EncryptLarge(personC.GenerateRandomString(personD.bulletin));
            personD.bulletin = personB.EncryptLarge(personB.GenerateRandomString(personD.bulletin));
            personD.bulletin = personA.EncryptLarge(personA.GenerateRandomString(personD.bulletin));

            //send all bulletins to A
            personA.RecieveBulletin(personA.bulletin);
            personA.RecieveBulletin(personB.bulletin);
            personA.RecieveBulletin(personC.bulletin);
            personA.RecieveBulletin(personD.bulletin);

            personA.DecryptAllLarge();
            personA.CheckBulletins();
            personA.RemoveStrings();

            personB.recievedBulletins = personA.recievedBulletins;
            personA.recievedBulletins = null;

            personB.DecryptAllLarge();
            personB.CheckBulletins();
            personB.RemoveStrings();

            personC.recievedBulletins = personB.recievedBulletins;
            personB.recievedBulletins = null;

            personC.DecryptAllLarge();
            personC.CheckBulletins();
            personC.RemoveStrings();

            personD.recievedBulletins = personC.recievedBulletins;
            personC.recievedBulletins = null;

            personD.DecryptAllLarge();
            personD.CheckBulletins();
            personD.RemoveStrings();

            //send all to A again
            personA.recievedBulletins = personD.recievedBulletins;
            personD.recievedBulletins = null;

            personA.DecryptAll();
            personA.CheckBulletins();
            personA.SignBulletins();

            //send to B
            personB.recievedBulletins = personA.recievedBulletins;
            personA.recievedBulletins = null;

            personB.VerifySigns(personA.PublicSignKey);
            personB.DecryptAll();
            personB.CheckBulletins();
            personB.SignBulletins();

            //send to C

            personC.recievedBulletins = personB.recievedBulletins;
            personB.recievedBulletins = null;

            personC.VerifySigns(personB.PublicSignKey);
            personC.DecryptAll();
            personC.CheckBulletins();
            personC.SignBulletins();

            //send to D

            personD.recievedBulletins = personC.recievedBulletins;
            personC.recievedBulletins = null;

            personD.VerifySigns(personB.PublicSignKey);
            personD.DecryptAll();
            personD.CheckBulletins();
            personD.SignBulletins();

            personA.recievedBulletins = personD.recievedBulletins;
            personB.recievedBulletins = personD.recievedBulletins;
            personC.recievedBulletins = personD.recievedBulletins;

            personA.VerifySigns(personD.PublicSignKey);
            personB.VerifySigns(personD.PublicSignKey);
            personC.VerifySigns(personD.PublicSignKey);

            List<string> applicants = new List<string>();

            foreach (var item in personD.recievedBulletins)
            {
                applicants.Add(Encoding.UTF8.GetString(item).Substring(0, 1));
            }

            for (int i = 1; i < 5; i++)
            {
                Console.WriteLine($"{i} applicant :{applicants.Count(x => x == i.ToString())}");
            }
        }
    }
    
}
