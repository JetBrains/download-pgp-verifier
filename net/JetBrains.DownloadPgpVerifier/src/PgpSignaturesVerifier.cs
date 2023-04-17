using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg.Sig;

namespace JetBrains.DownloadPgpVerifier
{
  public static class PgpSignaturesVerifier
  {
    public static readonly string MasterPublicKey = LoadMasterPublicKeyFromResources();
    public static readonly Uri PublicKeysUri = new("https://download.jetbrains.com/KEYS");

    public static bool Verify(
      Stream masterPublicKeyStream,
      Stream publicKeysStream,
      Stream signaturesStream,
      Stream dataStream,
      ILogger logger)
    {
      if (dataStream == null) throw new ArgumentNullException(nameof(dataStream));
      if (logger == null) throw new ArgumentNullException(nameof(logger));
      var pos = dataStream.CanSeek ? dataStream.Position : throw new ArgumentException("The data stream must be seek-able", nameof(dataStream));
      logger.Info("Verify");

      var masterPublicKey = GetTrustedMasterPublicKey(masterPublicKeyStream);
      var publicKeyRingBundle = GetUntrustedPublicKeyRingBundle(publicKeysStream);
      var buffer = new byte[16 * 1024];
      foreach (var signature in GetSignatures(signaturesStream))
        if (signature.SignatureType is PgpSignature.BinaryDocument)
        {
          void LogWarning(string str) => logger.Warning($"The signature SignKeyID={signature.KeyId:X16} was skipped: {str}");

          if (!CheckSignatureFormat(signature, LogWarning))
            continue;

          var publicKey = publicKeyRingBundle.GetPublicKey(signature.KeyId);
          if (publicKey == null)
          {
            LogWarning("No public key for signature");
            continue;
          }

          if (!CheckPublicKeyFormat(publicKey, LogWarning))
            continue;

          if (!IsSubKeyForSigning(masterPublicKey, publicKey, LogWarning))
            continue;

          if (!IsSubKeyRevoked(masterPublicKey, publicKey, signature, LogWarning))
            continue;

          signature.InitVerify(publicKey);
          dataStream.Position = pos;
          while (true)
          {
            var received = dataStream.Read(buffer, 0, buffer.Length);
            if (received == 0)
              break;
            signature.Update(buffer, 0, received);
          }

          if (!signature.Verify())
          {
            LogWarning("Invalid signature verification.");
            continue;
          }

          logger.Info($"Success for SignKeyID={signature.KeyId:X16}");
          return true;
        }

      logger.Error("Failed to verify signature");
      return false;
    }

    private static PgpPublicKey GetTrustedMasterPublicKey(Stream stream)
    {
      if (stream == null) throw new ArgumentNullException(nameof(stream));
      using var decodedStream = PgpUtilities.GetDecoderStream(stream);
      var bundle = new PgpPublicKeyRingBundle(decodedStream);
      var ring = bundle.GetKeyRings().Cast<PgpPublicKeyRing>().SingleOrDefault() ?? throw new Exception("Only one key ring is expected");
      var publicKey = ring.GetPublicKeys().Cast<PgpPublicKey>().SingleOrDefault() ?? throw new Exception("Only one public key is expected");
      if (!publicKey.IsMasterKey)
        throw new Exception($"Master key is required. KeyID={publicKey.KeyId:X16}");
      CheckPublicKeyFormat(publicKey, err => throw new Exception(err));
      return publicKey;
    }

    private static PgpPublicKeyRingBundle GetUntrustedPublicKeyRingBundle(Stream stream)
    {
      if (stream == null) throw new ArgumentNullException(nameof(stream));
      using var decodedStream = PgpUtilities.GetDecoderStream(stream);
      return new PgpPublicKeyRingBundle(decodedStream);
    }

    private static IEnumerable<PgpSignature> GetSignatures(Stream stream)
    {
      static IEnumerable<PgpSignature> ToEnumerable(PgpSignatureList list)
      {
        return Enumerable.Range(0, list.Count).Select(x => list[x]).ToList();
      }

      using var decodedStream = PgpUtilities.GetDecoderStream(stream);
      var factory = new PgpObjectFactory(decodedStream);
      for (PgpObject obj; (obj = factory.NextPgpObject()) != null;)
        switch (obj)
        {
        case PgpCompressedData data:
          using (var dataStream = data.GetDataStream())
          {
            var factory2 = new PgpObjectFactory(dataStream);
            for (PgpObject obj2; (obj2 = factory2.NextPgpObject()) != null;)
              if (obj2 is PgpSignatureList list)
                return ToEnumerable(list);
          }

          break;
        case PgpSignatureList list:
          return ToEnumerable(list);
        }

      throw new Exception("No PGP signature was found");
    }

    private static bool IsSubKeyForSigning(PgpPublicKey masterPublicKey, PgpPublicKey publicKey, Action<string> onError)
    {
      if (masterPublicKey == null) throw new ArgumentNullException(nameof(masterPublicKey));
      if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
      if (onError == null) throw new ArgumentNullException(nameof(onError));
      if (!masterPublicKey.IsMasterKey)
        throw new Exception($"Master key is required. KeyID={masterPublicKey.KeyId:X16}");
      if (publicKey.IsMasterKey)
        throw new Exception($"Sub key is required. KeyID={publicKey.KeyId:X16}");

      foreach (PgpSignature signature in publicKey.GetKeySignatures())
        if (signature.SignatureType == PgpSignature.SubkeyBinding)
          if ((signature.GetHashedSubPackets().GetKeyFlags() & KeyFlags.SignData) != 0)
            if (CheckSignatureFormat(signature, onError))
            {
              signature.InitVerify(masterPublicKey);
              if (signature.VerifyCertification(masterPublicKey, publicKey))
                return true;
              onError($"Failed to verify the certification of the signature MasterKeyID={masterPublicKey.KeyId:X16} SubKeyID={publicKey.KeyId:X16}");
            }

      onError($"Incompatible keys MasterKeyID={masterPublicKey.KeyId:X16} SubKeyID={publicKey.KeyId:X16}");
      return false;
    }

    private static bool IsSubKeyRevoked(PgpPublicKey masterPublicKey, PgpPublicKey publicKey, PgpSignature signature, Action<string> onError)
    {
      if (masterPublicKey == null) throw new ArgumentNullException(nameof(masterPublicKey));
      if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
      if (signature == null) throw new ArgumentNullException(nameof(signature));
      if (onError == null) throw new ArgumentNullException(nameof(onError));
      if (!masterPublicKey.IsMasterKey)
        throw new Exception($"Master key is required. KeyID={masterPublicKey.KeyId:X16}");
      if (publicKey.IsMasterKey)
        throw new Exception($"Sub key is required. KeyID={publicKey.KeyId:X16}");
      foreach (PgpSignature revocationSignature in publicKey.GetSignatures())
        if (revocationSignature.SignatureType == PgpSignature.SubkeyRevocation)
          if (CheckSignatureFormat(revocationSignature, onError))
          {
            revocationSignature.InitVerify(masterPublicKey);
            if (!revocationSignature.VerifyCertification(masterPublicKey, publicKey))
            {
              onError($"Failed to verify the certification of the revocation signature MasterKeyID={masterPublicKey.KeyId:X16} SubKeyID={publicKey.KeyId:X16}");
              return false;
            }

            if (revocationSignature.CreationTime <= signature.CreationTime)
            {
              onError($"The signature for SignKeyID={signature.KeyId:X16} was revoked");
              return false;
            }
          }

      return true;
    }

    private static bool CheckSignatureFormat(PgpSignature signature, Action<string> onError)
    {
      if (signature == null) throw new ArgumentNullException(nameof(signature));
      if (onError == null) throw new ArgumentNullException(nameof(onError));
      if (signature.HashAlgorithm != HashAlgorithmTag.Sha256 &&
          signature.HashAlgorithm != HashAlgorithmTag.Sha384 &&
          signature.HashAlgorithm != HashAlgorithmTag.Sha512)
      {
        onError($"Only hashAlgorithms SHA256/384/512 are supported. See https://tools.ietf.org/html/rfc4880#section-9.4. SignKeyID={signature.KeyId:X16}");
        return false;
      }

      if (signature.KeyAlgorithm != PublicKeyAlgorithmTag.RsaGeneral)
      {
        onError($"Only keyAlgorithm = 1 (RSA (Encrypt or Sign)) is supported. See https://tools.ietf.org/html/rfc4880#section-9.1. SignKeyID={signature.KeyId:X16}");
        return false;
      }

      return true;
    }

    private static bool CheckPublicKeyFormat(PgpPublicKey key, Action<string> onError)
    {
      if (key == null) throw new ArgumentNullException(nameof(key));
      if (onError == null) throw new ArgumentNullException(nameof(onError));
      if (key.Version != 4)
      {
        onError($"Only PGP public keys version 4 are supported. KeyID={key.KeyId:X16}");
        return false;
      }

      if (key.BitStrength < 2048)
      {
        onError($"Only PGP public keys bits>=2048 are supported. KeyID={key.KeyId:X16}");
        return false;
      }

      return true;
    }

    private static string LoadMasterPublicKeyFromResources()
    {
      var type = typeof(PgpSignaturesVerifier);
      return type.Assembly.OpenStreamFromResource(type.Namespace + ".Resources.real-master-public-key.asc", stream =>
        {
          using var reader = new StreamReader(stream, Encoding.ASCII);
          return reader.ReadToEnd();
        });
    }
  }
}