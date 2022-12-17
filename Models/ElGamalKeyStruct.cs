
namespace laba4_vote.Models
{
    public struct ElGamalKeyStruct
    {
        //Those will be contained inside the public key
        public BigInteger P;
        public BigInteger G;
        public BigInteger Y;

        //This will be the private key
        public BigInteger X;

    }
}