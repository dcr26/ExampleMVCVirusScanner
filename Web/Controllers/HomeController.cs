using System.Web;
using System.Web.Mvc;
using Web.Classes;
using Web.Models;

namespace Web.Controllers {
    /// <summary>
    /// Main controller
    /// </summary>
    public class HomeController : Controller {
        
        /// <summary>
        /// Get the upload view
        /// </summary>
        [HttpGet]
        public ActionResult Index() {
            return View();
        }

        /// <summary>
        /// Handle the file upload
        /// </summary>
        [HttpPost]
        public ActionResult Index(UploadViewModel model, HttpPostedFileBase file) {
            var scanner = VirusScannerFactory.GetVirusScanner();
            var result = scanner.ScanStream(file.InputStream);
            ViewBag.Message = result.Message;
            return View(model);
        }
    }
}