using System.Security.Cryptography;

namespace laba4_vote.Models
{
    public abstract class ElGamal : AsymmetricAlgorithm
    {
        public abstract void ImportParameters(ElGamalKeyStruct keyStruct);
        public abstract byte[] Sign(byte[] p_hashcode);
        public abstract bool Verify(byte[] data, byte[] signature);
    }
}