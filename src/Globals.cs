using System.Text;

namespace phantom.MVC.MuOnline
{
    public class Globals
    {
        const string _jwtSecretKey = "Hz0SWiDLPxHhZzxSlZEZgBsHuQWniKsNqAhqz4MByhKmSrYxxHerPXiBV/bG1Q2g0AIVlanUR7iVhEZF4fwes6h5eGCQh0XASLf6QukWPcVTeJcK78qCzl/QFJUIzSrwhkx/VSkP6jBkn++dUEyjXw==";
        public static byte[] JwtSecretKey
        {
            get
            {
                return Encoding.ASCII.GetBytes(_jwtSecretKey);
            }
        }
        public const int TokenTimeout = 30;
    }
}
