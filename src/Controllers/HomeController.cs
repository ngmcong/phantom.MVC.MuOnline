using System;
using System.Data;
using System.Data.Common;
using System.Diagnostics;
using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using phantom.MVC.MuOnline.Models;

namespace phantom.MVC.MuOnline.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly string _connectionString = "Data Source=192.168.2.199;Initial Catalog=MuOnline;User ID=sa;Password=;TrustServerCertificate=True;";

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<APIModel> Register([FromBody] RegisterModel model)
        {
            try
            {
                string guid = string.Empty;
                for (int i = 0; i < 18; i++)
                {
                    guid += (new Random()).Next(0, 9);
                }
                using (DbCommand dbCommand = new SqlCommand($"SELECT memb___id,mail_addr FROM [MEMB_INFO] WHERE memb___id='{model.Name}' OR mail_addr='{model.Email}'"))
                using (DbConnection dbConnection = new SqlConnection(_connectionString))
                {
                    dbCommand.CommandType = System.Data.CommandType.Text;
                    dbCommand.Connection = dbConnection;
                    DbDataAdapter dbDataAdapter = new SqlDataAdapter((SqlCommand)dbCommand);
                    DataTable dataTable = new DataTable();
                    dbDataAdapter.Fill(dataTable);
                    if (dataTable.Rows.Count > 0)
                    {
                        return new APIModel("Đã tồn tại tài khoản.");
                    }
                    await dbConnection.OpenAsync();
                    using (DbTransaction dbTransaction = dbConnection.BeginTransaction())
                    {
                        dbCommand.Transaction = dbTransaction;
                        dbCommand.CommandText = $"INSERT INTO [MEMB_INFO] (memb___id,mail_addr,memb_name,sno__numb,bloc_code,ctl1_code) VALUES ('{model.Name}','{model.Email}','phantom','{guid}',0,1)";
                        var retQueries = await dbCommand.ExecuteNonQueryAsync();
                        if (retQueries <= 0)
                        {
                            await dbTransaction.RollbackAsync();
                            return new APIModel("Không thể tạo được thông tin tài khoản.");
                        }
                        dbCommand.CommandText = $"exec SP_MD5_ENCODE_VALUE @btInStr='{model.Password}',@btInStrIndex='{model.Name}'";
                        retQueries = await dbCommand.ExecuteNonQueryAsync();
                        if (retQueries <= 0)
                        {
                            await dbTransaction.RollbackAsync();
                            return new APIModel("Không thể tạo được thông tin tài khoản.");
                        }
                        await dbTransaction.CommitAsync();
                    }
                }
                return new APIModel();
            }
            catch (Exception ex)
            {
                return new APIModel(ex.Message);
            }
        }
    }

    public class MEMB_INFO
    {
        public string? memb___id { get; set; }
        public string? mail_addr { get; set; }
    }

    public class RegisterModel
    {
        public string? Name { get; set; }
        public string? Email { get; set; }
        public string? Password { get; set; }
    }

    public class APIModel
    {
        public short RetCode { get; set; }
        public string? Message { get; set; }

        public APIModel() { }
        public APIModel(string message)
        {
            Message = message;
            RetCode = 1;
        }
    }
}
