using System;
using System.IO;
using System.Linq;
using nClam;

namespace Web.Classes {
    /// <summary>
    /// Implmemntation of Clam AV to scan viruses
    /// </summary>
    public class ClamAvScanner : IScanViruses {
        /// <summary>
        /// Scans a file for viruses
        /// </summary>
        /// <param name="pathToFile">The full path to the file</param>
        public ScanResult ScanFile(string pathToFile) {
            var clam = new ClamClient("localhost", 3310);
            return MapScanResult(clam.ScanFileOnServer(pathToFile));
        }
        
        /// <summary>
        /// Scans some bytes for virus
        /// </summary>
        /// <param name="data">byte data to scan</param>
        public ScanResult ScanBytes(byte[] data) {
            var clam = new ClamClient("localhost", 3310);
            return MapScanResult(clam.SendAndScanFile(data));
        }

        /// <summary>
        /// Scans your data stream for virus
        /// </summary>
        /// <param name="stream">The stream you want to check</param>
        public ScanResult ScanStream(Stream stream) {
            var clam = new ClamClient("localhost", 3310);
            return MapScanResult(clam.SendAndScanFile(stream));
        
        }

        /// <summary>
        /// helper method to map scan results
        /// </summary>
        private ScanResult MapScanResult(ClamScanResult scanresult) {
            var result = new ScanResult();
            switch (scanresult.Result) {
                case ClamScanResults.Unknown:
                    result.Message = "Could not scan file";
                    result.IsVirusFree = false;
                    break;
                case ClamScanResults.Clean:
                    result.Message = "No Virus found";
                    result.IsVirusFree = true;
                    break;
                case ClamScanResults.VirusDetected:
                    result.Message = "Virus found: " + scanresult.InfectedFiles.First().VirusName;
                    result.IsVirusFree  = false;
                    break;
                case ClamScanResults.Error:
                    result.Message = string.Format("VIRUS SCAN ERROR! {0}", scanresult.RawResult);
                    result.IsVirusFree  = false;
                    break;
            }
            return result;
        }
    }
}