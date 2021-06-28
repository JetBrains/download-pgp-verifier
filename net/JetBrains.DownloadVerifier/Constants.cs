using System;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace JetBrains.DownloadVerifier
{
  public static class Constants
  {
    public static readonly PgpPublicKey MasterPublicKey = typeof(KeysUtil).Assembly.OpenStreamFromResource(typeof(KeysUtil).Namespace + ".Resources.real-master-public-key.asc", KeysUtil.GetTrustedMasterPublicKey);
    public static readonly Uri PublicKeysUri = new("https://download.jetbrains.com/KEYS");
  }
}