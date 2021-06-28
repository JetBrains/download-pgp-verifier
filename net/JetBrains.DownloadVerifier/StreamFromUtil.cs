using System;
using System.IO;
using System.Net;
using System.Reflection;
using JetBrains.Annotations;

namespace JetBrains.DownloadVerifier
{
  public static class StreamFromUtil
  {
    public static TResult OpenStreamFromResource<TResult>([NotNull] this Assembly assembly, [NotNull] string resourceName, [NotNull] Func<Stream, TResult> handler)
    {
      if (assembly == null) throw new ArgumentNullException(nameof(assembly));
      if (handler == null) throw new ArgumentNullException(nameof(handler));
      using var stream = assembly.GetManifestResourceStream(resourceName);
      if (stream == null)
        throw new InvalidOperationException($"Failed to open resource stream for {resourceName}");
      return handler(stream);
    }

    public static TResult OpenStreamFromWeb<TResult>([NotNull] this Uri uri, [NotNull] Func<Stream, TResult> handler)
    {
      if (handler == null) throw new ArgumentNullException(nameof(handler));
      var request = (HttpWebRequest) WebRequest.Create(uri);
      request.Method = WebRequestMethods.Http.Get;
      using var response = (HttpWebResponse) request.GetResponse();
      using var responseStream = response.GetResponseStream();
      if (responseStream == null)
        throw new InvalidOperationException($"Failed to open response stream for {uri}");
      using var fileStream = new FileStream(Path.GetTempFileName(), FileMode.Create, FileAccess.ReadWrite, FileShare.None, 8192, FileOptions.DeleteOnClose | FileOptions.RandomAccess);
      responseStream.CopyTo(fileStream);
      fileStream.Position = 0;
      return handler(fileStream);
    }
  }
}