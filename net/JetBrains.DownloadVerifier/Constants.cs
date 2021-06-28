using System;
using System.IO;
using System.Text;
using JetBrains.Annotations;

namespace JetBrains.DownloadVerifier
{
  public static class Constants
  {
    public static readonly string MasterPublicKey = GetMasterPublicKey();
    public static readonly Uri PublicKeysUri = new("https://download.jetbrains.com/KEYS");

    [NotNull]
    private static string GetMasterPublicKey()
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