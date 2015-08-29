using System.IO;

namespace Web.Classes {
    /// <summary>
    ///     Interface for us to implement
    /// </summary>
    public interface IScanViruses {
        /// <summary>
        ///     Scans a file for a virus
        /// </summary>
        /// <param name="fullPath">The full path to the file</param>
        ScanResult ScanFile(string fullPath);

        /// <summary>
        ///     Scans some bytes for a virus
        /// </summary>
        /// <param name="bytes">The bytes to scan</param>
        ScanResult ScanBytes(byte[] bytes);

        /// <summary>
        ///     Scans a stream for a virus
        /// </summary>
        /// <param name="stream">The stream to scan</param>
        ScanResult ScanStream(Stream stream);
    }
}