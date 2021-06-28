using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using JetBrains.Annotations;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg.Sig;

namespace JetBrains.DownloadVerifier
{
  public static class PgpSignaturesVerifier
  {
    public static bool Verify(
      [NotNull] Stream masterPublicKeyStream,
      [NotNull] Stream publicKeysStream,
      [NotNull] Stream signaturesStream,
      [NotNull] Stream dataStream,
      [NotNull] ILogger logger)
    {
      if (dataStream == null) throw new ArgumentNullException(nameof(dataStream));
      if (logger == null) throw new ArgumentNullException(nameof(logger));
      var pos = dataStream.CanSeek ? dataStream.Position : throw new ArgumentException("The data stream must be seek-able", nameof(dataStream));
      logger.Info("Verify data");

      var masterPublicKey = GetTrustedMasterPublicKey(masterPublicKeyStream);
      var publicKeyRingBundle = GetUntrustedPublicKeyRingBundle(publicKeysStream);
      var buffer = new byte[16 * 1024];
      foreach (var signature in GetSignatures(signaturesStream))
        if (signature.SignatureType is PgpSignature.BinaryDocument or PgpSignature.CanonicalTextDocument)
        {
          if (!CheckSignatureFormat(signature, x => logger.Warning("The signature was skipped: " + x)))
            continue;

          var publicKey = publicKeyRingBundle.GetPublicKey(signature.KeyId);
          if (publicKey == null)
            continue;
          if (!CheckPublicKeyFormat(publicKey, x => logger.Warning("The subkey was skipped: " + x)))
            continue;

          if (!IsSubKeyForSigning(masterPublicKey, publicKey, x => logger.Warning("The subkey was skipped: " + x)))
            continue;

          if (!CheckRevoked(publicKey, signature, x => logger.Warning("The subkey was skipped: " + x)))
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
            logger.Warning($"The signature was skipped: Invalid verification. SignKetID={signature.KeyId:X16}");
            continue;
          }

          logger.Info($"Success for SignKetID={signature.KeyId:X16}");
          return true;
        }

      logger.Error("Failed to verify signature");
      return false;
    }

    [NotNull]
    private static PgpPublicKey GetTrustedMasterPublicKey([NotNull] Stream stream)
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

    [NotNull]
    private static PgpPublicKeyRingBundle GetUntrustedPublicKeyRingBundle([NotNull] Stream stream)
    {
      if (stream == null) throw new ArgumentNullException(nameof(stream));
      using var decodedStream = PgpUtilities.GetDecoderStream(stream);
      return new PgpPublicKeyRingBundle(decodedStream);
    }

    [NotNull]
    private static IEnumerable<PgpSignature> GetSignatures([NotNull] Stream stream)
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

    private static bool CheckRevoked(PgpPublicKey publicKey, PgpSignature signature, Action<string> onError)
    {
      foreach (PgpSignature revocationSignature in publicKey.GetSignatures())
        if (revocationSignature.SignatureType == PgpSignature.SubkeyRevocation)
          if (revocationSignature.CreationTime <= signature.CreationTime)
          {
            onError($"The signature for SignKeyID={signature.KeyId:X16} was revoked");
            return false;
          }

      return true;
    }

    private static bool IsSubKeyForSigning([NotNull] PgpPublicKey masterPublicKey, [NotNull] PgpPublicKey publicKey, [NotNull] Action<string> onError)
    {
      if (!masterPublicKey.IsMasterKey)
        throw new Exception($"Master key is required. KeyID={masterPublicKey.KeyId:X16}");
      if (publicKey.IsMasterKey)
        throw new Exception($"Sub key is required. KeyID={publicKey.KeyId:X16}");

      foreach (PgpSignature signature in publicKey.GetKeySignatures())
        if (signature.SignatureType == PgpSignature.SubkeyBinding)
          if ((signature.GetHashedSubPackets().GetKeyFlags() & KeyFlags.SignData) != 0)
            if (CheckSignatureFormat(signature, _ => { }))
            {
              signature.InitVerify(masterPublicKey);
              if (signature.VerifyCertification(masterPublicKey, publicKey))
                return true;
            }

      onError($"Incompatible keys MasterKeyID={masterPublicKey.KeyId:X16} SubKeyID={publicKey.KeyId:X16}");
      return false;
    }

    private static bool CheckSignatureFormat([NotNull] PgpSignature signature, [NotNull] Action<string> onError)
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

    private static bool CheckPublicKeyFormat([NotNull] PgpPublicKey key, [NotNull] Action<string> onError)
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
  }
}