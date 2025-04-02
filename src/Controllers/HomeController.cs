using System.Data;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Tokens;
using phantom.Core.Crypto;
using phantom.Core.WZMD5MOD;
using phantom.MVC.MuOnline.Models;

namespace phantom.MVC.MuOnline.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

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
                model.Password = CryptoHelper.DecryptString(model.Password!);
                string guid = string.Empty;
                for (int i = 0; i < 18; i++)
                {
                    guid += (new Random()).Next(0, 9);
                }
                using (var dbConnection = new SqlDbConnection())
                {
                    var dataTable = dbConnection.Fill($"SELECT memb___id,mail_addr FROM [MEMB_INFO] WHERE memb___id='{model.Name}' OR mail_addr='{model.Email}'");
                    if (dataTable.Rows.Count > 0)
                    {
                        return new APIModel("Đã tồn tại tài khoản.");
                    }
                    dbConnection.OpenTransaction();
                    var retQueries = await dbConnection.ExecuteNonQueryAsync($"INSERT INTO [MEMB_INFO] (memb___id,mail_addr,memb_name,sno__numb,bloc_code,ctl1_code) VALUES ('{model.Name}','{model.Email}','phantom','{guid}',0,1)");
                    if (retQueries <= 0)
                    {
                        dbConnection.RollbackTransaction();
                        return new APIModel("Không thể tạo được thông tin tài khoản.");
                    }
                    retQueries = await dbConnection.ExecuteNonQueryAsync($"EXEC SP_MD5_ENCODE_VALUE @btInStr='{model.Password}',@btInStrIndex='{model.Name}'");
                    if (retQueries <= 0)
                    {
                        dbConnection.RollbackTransaction();
                        return new APIModel("Không thể tạo được thông tin tài khoản.");
                    }
                    dbConnection.CommitTransaction();
                }
                return new APIModel();
            }
            catch (Exception ex)
            {
                return new APIModel(ex.Message);
            }
        }

        private string Base64Encode(string input, string accountName)
        {
            MUMD5 md5Hash = new MUMD5();

            int dwAccKey = md5Hash.MakeAccountKey(accountName);

            md5Hash.SetMagicNum(dwAccKey);
            md5Hash.Update(Encoding.UTF8.GetBytes(input), input.Length);

            byte[] digest = md5Hash.FinalizeMD5();
            byte[] finalDigest = md5Hash.GetDigest();
            string finalString = Convert.ToBase64String(finalDigest);

            return finalString;
        }

        private string CreateLoginToken(string accountId)
        {
            //Authentication successful so generate jwt token
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, $"{accountId}"),
                    new Claim(ClaimTypes.Name, $"{accountId}"),
                }),
                Expires = DateTime.UtcNow.AddMinutes(Globals.TokenTimeout),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Globals.JwtSecretKey), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var stringToken = tokenHandler.WriteToken(token);
            return stringToken;
        }

        [HttpPost]
        public async Task<APIModel> Login([FromBody] RegisterModel model)
        {
            try
            {
                if (string.IsNullOrEmpty(model.Name) || string.IsNullOrEmpty(model.Password))
                {
                    return new APIModel("Tên tài khoản hoặc mật khẩu không được để trống.");
                }
                model.Password = CryptoHelper.DecryptString(model.Password!);
                using (var dbConnection = new SqlDbConnection())
                {
                    var memb__pwd = $"{await dbConnection.ExecuteScalarAsync($"SET ARITHABORT ON; SELECT TOP 1 CAST('' AS XML).value('xs:base64Binary(sql:column(\"memb__pwd\"))', 'varchar(max)') AS memb__pwd FROM [MEMB_INFO] WHERE memb___id='{model.Name}'")}";
                    if (Base64Encode(model.Password!, model.Name!) == memb__pwd)
                    {
                        var stringToken = CreateLoginToken(model.Name!);
                        return new APIModel(new { Token = stringToken });
                    }
                }
                return new APIModel("Sai thông tin tài khoản.");
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
        public object? Data { get; set; }

        public APIModel() { }
        public APIModel(object? data) => Data = data;
        public APIModel(string message)
        {
            Message = message;
            RetCode = 1;
        }
    }
}
