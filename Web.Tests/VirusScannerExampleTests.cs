using System;
using System.IO;
using System.Reflection;
using System.Text;
using NUnit.Framework;
using Web.Classes;

namespace Web.Tests {
    [TestFixture]
    public class VirusScannerExampleTests {
        /// <summary>
        /// Test files on disk. I have taken naughty.txt out 
        /// because github may complain about the virus file and my 
        /// antivirus keeps removing it.
        /// </summary>
        [TestCase("clean.jpg", true)]
        //[TestCase("naughty.txt", false)] You need to create this file, and add it to your antivirus exclusions
        public void Can_scan_a_file_for_virus(string file, bool expectedToBeVirusFree) {
            string fullPath = Path.Combine(GetAssemblyDirectory(), "VirusScannerFiles") + "\\" + file;
            var scanner = VirusScannerFactory.GetVirusScanner();
            var result = scanner.ScanFile(fullPath);
            Assert.That(result.IsVirusFree, Is.EqualTo(expectedToBeVirusFree), result.Message);
        }

        /// <summary>
        /// Test bytes uploaded 
        /// </summary>
        [TestCase("Here is a nice clean string with nothing bad in it", true)]
        [TestCase(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", false)]
        public void Can_scan_bytes_for_virus(string stringData, bool expectedToBeVirusFree) {
            byte[] bytes = Encoding.ASCII.GetBytes(stringData);
            var scanner = VirusScannerFactory.GetVirusScanner();
            var result = scanner.ScanBytes(bytes);
            Assert.That(result.IsVirusFree, Is.EqualTo(expectedToBeVirusFree), result.Message);
        }
        
        /// <summary>
        /// Test scanning a memory stream, typically what we get from a MVC http file base
        /// </summary>
        [TestCase("Here is another nice clean string to scan for viruses", true)]
        [TestCase(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", false)]
        public void Can_scan_memory_stream_for_virus(string stringData, bool expectedToBeVirusFree) {
            var stream = new MemoryStream(Encoding.ASCII.GetBytes(stringData));
            var scanner = VirusScannerFactory.GetVirusScanner();
            var result = scanner.ScanStream(stream);
            Assert.That(result.IsVirusFree, Is.EqualTo(expectedToBeVirusFree), result.Message);
        }

        /// <summary>
        /// Help methos to get path of executing assembly
        /// </summary>
        /// <returns>Returns the full path to the currently executing assembly</returns>
        private string GetAssemblyDirectory() {
            string codeBase = Assembly.GetExecutingAssembly().CodeBase;
            var uri = new UriBuilder(codeBase);
            string path = Uri.UnescapeDataString(uri.Path);
            return Path.GetDirectoryName(path);
        }
    }
}