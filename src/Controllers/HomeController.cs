using System.Data;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OfficeOpenXml;
using phantom.Core.Crypto;
using phantom.Core.SQLClient;
using phantom.Core.WZMD5MOD;
using phantom.MVC.MuOnline.Models;

namespace phantom.MVC.MuOnline.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private static DataTable? _itemDb;
        private const string _connectionString = "Data Source=192.168.2.199;Initial Catalog=MuOnline;User ID=sa;Password=;TrustServerCertificate=True;";

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
                using (var dbConnection = new SqlDbConnection(_connectionString))
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

        private string CreateLoginToken(string accountId, string? originalToken = null)
        {
            //Authentication successful so generate jwt token
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, $"{accountId}"),
                    new Claim(ClaimTypes.Name, $"{accountId}"),
                    string.IsNullOrEmpty(originalToken) ?  new Claim("scope", "read:users write:users") : new Claim("scope", "read:refresh"),
                    new Claim("OriginalToken", $"{originalToken}"),
                }),
                Expires = string.IsNullOrEmpty(originalToken) ? DateTime.UtcNow.AddMinutes(Globals.TokenTimeout) : null,
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
                using (var dbConnection = new SqlDbConnection(_connectionString))
                {
                    var memb__pwd = $"{await dbConnection.ExecuteScalarAsync($"SET ARITHABORT ON; SELECT TOP 1 CAST('' AS XML).value('xs:base64Binary(sql:column(\"memb__pwd\"))', 'varchar(max)') AS memb__pwd FROM [MEMB_INFO] WHERE memb___id='{model.Name}'")}";
                    if (Base64Encode(model.Password!, model.Name!) == memb__pwd)
                    {
                        var token = CreateLoginToken(accountId: model.Name!);
                        return new APIModel(new
                        {
                            Token = token,
                            RefreshToken = CreateLoginToken(accountId: model.Name!, originalToken: token)
                        });
                    }
                }
                return new APIModel("Sai thông tin tài khoản.");
            }
            catch (Exception ex)
            {
                return new APIModel(ex.Message);
            }
        }

        public IActionResult ChangePass()
        {
            return View();
        }

        [HttpGet, Authorize(Policy = "Refresh")]
        public async Task<ActionResult<APIModel>> Refresh([FromBody] string originalToken)
        {
            var refreshAccount = this.User.Claims.First(i => i.Type == ClaimTypes.NameIdentifier).Value;
            var refreshOriginalToken = this.User.Claims.First(i => i.Type == "OriginalToken").Value;

            var securityToken = (JwtSecurityToken)(new JwtSecurityTokenHandler()).ReadToken(originalToken);
            var originalAccount = securityToken.Claims.FirstOrDefault(c => c.Type == "nameid")?.Value;

            if (originalAccount != refreshAccount || refreshOriginalToken != originalToken)
            {
                return Unauthorized();
            }
            var token = CreateLoginToken(accountId: refreshAccount);
            await Task.CompletedTask;
            return new APIModel(new
            {
                Token = token,
                RefreshToken = CreateLoginToken(accountId: refreshAccount, originalToken: token)
            });
        }

        [HttpPost, Authorize(Policy = "User")]
        public async Task<APIModel> ChangePass([FromBody] RegisterModel model)
        {
            try
            {
                var loginVal = await Login(model);
                if (loginVal.RetCode != 0)
                {
                    return new APIModel("Sai thông tin tài khoản.");
                }
                model.NewPassword = CryptoHelper.DecryptString(model.NewPassword!);
                using (var dbConnection = new SqlDbConnection(_connectionString))
                {
                    var retQueries = await dbConnection.ExecuteNonQueryAsync($"EXEC SP_MD5_ENCODE_VALUE @btInStr='{model.NewPassword}',@btInStrIndex='{model.Name}'");
                    if (retQueries <= 0)
                    {
                        return new APIModel("Không thể tạo được thông tin tài khoản.");
                    }
                }
                return new APIModel();
            }
            catch (Exception ex)
            {
                return new APIModel(ex.Message);
            }
        }

        private IEnumerable<IEnumerable<T>> SplitToSublists<T>(IEnumerable<T> source, int size = 16)
        {
            return source
                     .Select((x, i) => new { Index = i, Value = x })
                     .GroupBy(x => x.Index / size)
                     .Select(x => x.Select(v => v.Value).ToList())
                     .ToList();
        }

        public IActionResult Market()
        {
            using (SqlDbConnection sqlDbConnection = new SqlDbConnection(_connectionString))
            {
                try
                {
                    string query = "SELECT Items FROM [warehouse]";
                    var data = sqlDbConnection.ExecuteScalarAsync(query).Result as byte[];
                    var sublists = SplitToSublists(data!);
                    var sublist2 = SplitToSublists(sublists!, 8);
                    bool[,] bools = new bool[15, 8];

                    if (_itemDb == null)
                    {
                        _itemDb = new DataTable();
                        using (var package = new ExcelPackage(new FileInfo("G:\\Projects\\phantom\\phantom.MVC.MuOnline\\src\\wwwroot\\db\\Items.xlsx")))
                        {
                            bool hasHeader = true; // Set to true if the first row contains headers
                            ExcelWorksheet worksheet = package.Workbook.Worksheets[0]; // Assuming the first sheet
                            int rowCount = worksheet.Dimension.Rows;
                            int colCount = worksheet.Dimension.Columns;
                            // Add columns to DataTable
                            for (int col = 1; col <= colCount; col++)
                            {
                                _itemDb.Columns.Add(worksheet.Cells[1, col].Value?.ToString() ?? $"Column{col}"); //handles null header values.
                            }
                            // Add rows to DataTable
                            int startRow = hasHeader ? 2 : 1; // Skip header row if present.
                            for (int row = startRow; row <= rowCount; row++)
                            {
                                DataRow dataRow = _itemDb.NewRow();
                                for (int col = 1; col <= colCount; col++)
                                {
                                    dataRow[col - 1] = worksheet.Cells[row, col].Value; // Handles null cell values.
                                }
                                _itemDb.Rows.Add(dataRow);
                            }
                        }
                    }

                    List<List<string>> tableCells = new List<List<string>>();
                    for (int y = 0; y < 15; y++)
                    {
                        tableCells.Add(new List<string> { "<td>&nbsp;&nbsp;</td>"
                            , "<td>&nbsp;&nbsp;</td>"
                            , "<td>&nbsp;&nbsp;</td>"
                            , "<td>&nbsp;&nbsp;</td>"
                            , "<td>&nbsp;&nbsp;</td>"
                            , "<td>&nbsp;&nbsp;</td>"
                            , "<td>&nbsp;&nbsp;</td>"
                            , "<td>&nbsp;&nbsp;</td>"
                        });
                    }
                    for (int x = 0; x < 8; x++)
                    {
                        for (int y = 0; y < 15; y++)
                        {
                            var item = sublist2.ElementAt(y).ElementAt(x);
                            if (item.Any(x => x != 255) == false) continue;
                            var id = item.ElementAt(0);
                            var tp = item.ElementAt(9) / 16;
                            DataRow[] results = _itemDb.Select($"TP = '{tp}' AND ID = '{id}'");
                            if (results.Length != 1)
                            {
                                throw new Exception("Error DB Item");
                            }
                            var fileImage = string.Format("{0:0000000}", Convert.ToInt32(results[0][0]));
                            var itemX = Convert.ToInt32(results[0]["X"]);
                            var itemY = Convert.ToInt32(results[0]["Y"]);
                            var imageHTML = $"<img style='cursor: pointer;' src=\"/images/items/{fileImage}.png\" />";
                            if (itemX == 1 && itemY == 1) tableCells[y][x] = $"<td>{imageHTML}</td>";
                            else tableCells[y][x] = $"<td colspan=\"{itemX}\" rowspan=\"{itemY}\">{imageHTML}</td>";
                            if (itemX != 1 || itemY != 1)
                            {
                                for (int ix = 0; ix < itemX; ix++)
                                {
                                    for (int iy = 0; iy < itemY; iy++)
                                    {
                                        if (ix == 0 && iy == 0) continue;
                                        tableCells[y + iy][x + ix] = string.Empty;
                                    }
                                }
                            }
                        }
                    }
                    var wareHouseHTML = $"<table id=\"warehouse\">{string.Join("", tableCells.Select(x => string.Join("", x.Where(c => string.IsNullOrEmpty(c) == false))).Select(x => $"<tr>{x}</tr>"))}</table>";
                    ViewBag.WareHouseHTML = wareHouseHTML;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
            return View();
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
        public string? NewPassword { get; set; }
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
