namespace Web.Classes {
    /// <summary>
    /// Virus scanner factory, should be extended to support other Anti virus applications
    /// </summary>
    public class VirusScannerFactory {
        public static IScanViruses GetVirusScanner() {
            //Currently we only have one Antivirus implementation, 
            //but later we want to include AVG, SOPHOS and metascan 
            return new ClamAvScanner();
        }
    }
}