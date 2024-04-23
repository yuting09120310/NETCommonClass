/*
 * 檔案名稱：Basic.cs
 * 程式功能：.NET 基礎通用 Function
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Data;
using System.Data.SqlClient;
using System.Net;
using System.Net.Http;
using System.Web;
using System.Security.Cryptography;


namespace NETCommonClass {
    public class Basic {
        /*** 全域宣告 START ****************************************************************/
        private SqlConnection conn = new SqlConnection();  // 資料庫物件

        public string appName = "";    // 應用程式名稱
        public string appPath = "";    // 應用程式所在路徑
        public string logDir = "";     // 記錄 Log 的目錄
        public string db_ConnectionString = "";  // 資料庫連線字串
        public int db_Command_TimeOut = 600;     // 資料庫指令執行時間(秒)
        public bool runtime_DeBug_Log = false;   // 是否要執行階段發生的錯誤訊息寫入記錄檔
        private readonly string pathSeparator = Path.DirectorySeparatorChar.ToString();  // 檔案路徑分格符號 ( \\ )
        /*** 全域宣告 END ******************************************************************/


        #region 初始化
        // Class 初始化
        public Basic() {
            appName = "";
            appPath = "";
            logDir = "";
            db_ConnectionString = "";
            db_Command_TimeOut = 600;
            runtime_DeBug_Log = false;
        }


        // 顯示元件版本
        public string Version() {
            return "VER 1.0.0 , Build Date : 2023-08-31 12:00:00";
        }


        // Class 釋放 START
        protected virtual void Dispose(bool disposing) {
        }


        public void Dispose() {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        // Class 釋放 END
        #endregion


        #region 資料庫存取
        // 資料庫連線
        public bool DB_Connection() {
            try {
                bool tmpResult = false;
                if (db_ConnectionString.Length == 0) { return false; }

                if (conn.State == ConnectionState.Closed) {
                    conn.ConnectionString = db_ConnectionString;
                    conn.Open();
                }

                if (conn.State == ConnectionState.Open) { tmpResult = true; }
                return tmpResult;

            }
            catch (Exception ex) {
                if (runtime_DeBug_Log == true) { LogMessage("[NETCommonClass.Basic.DB_Connection] 發生錯誤: " + ex.Message); }
                return false;
            }
        }


        // 關閉資料庫連線
        public void DB_Close() {
            try {
                conn.Close();
                return;
            }
            catch {
            }
        }


        // 執行 SQL 指令 (SQL 指令)
        public bool SqlExecute(string SQL) {
            try {
                if (conn.State == ConnectionState.Closed) { return false; }

                int tmpResult = -1;
                SqlCommand cmd = new SqlCommand(SQL, conn);
                cmd.CommandTimeout = db_Command_TimeOut;
                tmpResult = cmd.ExecuteNonQuery();
                cmd.Dispose();

                if (tmpResult >= 0) {
                    return true;
                }
                else {
                    return false;
                }

            }
            catch (Exception ex) {
                if (runtime_DeBug_Log == true) { LogMessage("[NETCommonClass.Basic.SqlExecute] 發生錯誤: " + ex.Message); }
                return false;
            }
        }


        // 執行 SQL 指令 (SQL 指令, 參數)
        public bool SqlExecute(string SQL, Dictionary<string, string> sqlParameters) {
            try {
                if (conn.State == ConnectionState.Closed) { return false; }

                int tmpResult = -1;
                SqlCommand cmd = new SqlCommand(SQL, conn);

                foreach (var items in sqlParameters) {
                    cmd.Parameters.AddWithValue(items.Key, items.Value);
                }

                cmd.CommandTimeout = db_Command_TimeOut;
                tmpResult = cmd.ExecuteNonQuery();
                cmd.Dispose();

                if (tmpResult >= 0) {
                    return true;
                }
                else {
                    return false;
                }

            }
            catch (Exception ex) {
                if (runtime_DeBug_Log == true) { LogMessage("[NETCommonClass.Basic.SqlExecute] 發生錯誤: " + ex.Message); }
                return false;
            }
        }


        // 取得 DataTable (SQL 指令)
        public DataTable GetDataTable(string SQL) {
            DataTable dt = new DataTable();

            try {
                if (conn.State == ConnectionState.Closed) { return dt; }

                SqlCommand cmd = new SqlCommand(SQL, conn);
                cmd.CommandTimeout = db_Command_TimeOut;
                SqlDataAdapter da = new SqlDataAdapter(cmd);
                da.Fill(dt);
                da.Dispose();
                cmd.Dispose();

            }
            catch (Exception ex) {
                if (runtime_DeBug_Log == true) { LogMessage("[NETCommonClass.Basic.GetDataTable] 發生錯誤: " + ex.Message); }
            }

            return dt;
        }


        // 取得 DataTable (SQL 指令, 參數)
        public DataTable GetDataTable(string SQL, Dictionary<string, string> sqlParameters) {
            DataTable dt = new DataTable();

            try {
                if (conn.State == ConnectionState.Closed) { return dt; }

                SqlCommand cmd = new SqlCommand(SQL, conn);

                foreach (var items in sqlParameters) {
                    cmd.Parameters.AddWithValue(items.Key, items.Value);
                }

                cmd.CommandTimeout = db_Command_TimeOut;
                SqlDataAdapter da = new SqlDataAdapter(cmd);
                da.Fill(dt);
                da.Dispose();
                cmd.Dispose();

            }
            catch (Exception ex) {
                if (runtime_DeBug_Log == true) { LogMessage("[NETCommonClass.Basic.GetDataTable] 發生錯誤: " + ex.Message); }
            }

            return dt;
        }


        // 取得 DataSet (SQL 指令)
        public DataSet GetDataSet(string SQL) {
            DataSet ds = new DataSet();

            try {
                if (conn.State == ConnectionState.Closed) { return ds; }

                SqlCommand cmd = new SqlCommand(SQL, conn);
                cmd.CommandTimeout = db_Command_TimeOut;
                SqlDataAdapter da = new SqlDataAdapter(cmd);
                da.Fill(ds);
                da.Dispose();
                cmd.Dispose();

            }
            catch (Exception ex) {
                if (runtime_DeBug_Log == true) { LogMessage("[NETCommonClass.Basic.GetDataSet] 發生錯誤: " + ex.Message); }
            }

            return ds;
        }


        // 取得 DataSet(SQL 指令, 參數)
        public DataSet GetDataSet(string SQL, Dictionary<string, string> sqlParameters) {
            DataSet ds = new DataSet();

            try {
                if (conn.State == ConnectionState.Closed) { return ds; }

                SqlCommand cmd = new SqlCommand(SQL, conn);

                foreach (var items in sqlParameters) {
                    cmd.Parameters.AddWithValue(items.Key, items.Value);
                }

                cmd.CommandTimeout = db_Command_TimeOut;
                SqlDataAdapter da = new SqlDataAdapter(cmd);
                da.Fill(ds);
                da.Dispose();
                cmd.Dispose();

            }
            catch (Exception ex) {
                if (runtime_DeBug_Log == true) { LogMessage("[NETCommonClass.Basic.GetDataSet] 發生錯誤: " + ex.Message); }
            }

            return ds;
        }


        // 資料 SQL Injection 檢核 (字串)
        public string InjectionCheck(string datas) {
            datas = datas.Replace("'", "''");

            return datas.Trim();
        }


        // 組 SQL，新增資料用 (SQL 字串, 資料庫欄位名, 變數值, 型別)
        /* $iType 型態可設定 int, float, str, datetime, date 五種
        範例：
        SQL = "";
        SQL = BSQL_I(SQL, "Num_Id", "123456", "int");
        SQL = BSQL_I(SQL, "WebSite", "https://123456", "");
        SQL = BSQL_I(SQL, "WebName", "客戶網站", "");
        SQL = "INSERT INTO [TableName] " + SQL;
        */
        public string BSQL_I(string tSQL, string iName, string iValue, string iType = "") {
            string[] arySQL;

            if (iType.Length == 0) { iType = "str"; }

            if (iType.Length > 0) {
                iType = iType.ToLower();

                if (iType == "int" || iType == "float") {
                    if (iValue == "") {
                        iValue = "0";
                    }
                    else {
                        if (int.TryParse(iValue, out int num1) == false) {
                            return "資料：" + iValue + " 型別不符：" + iType;
                        }
                    }
                }

                if (iType != "int" && iType != "float" && iType != "str" && iType != "datetime" && iType != "date") {
                    return "資料：" + iValue + " 設定之型別：" + iType + " 不允許";
                }
            }

            if (tSQL.Length > 0) {
                arySQL = this.Split(tSQL, ") VALUES (");
                arySQL[1] = arySQL[1].Substring(0, arySQL[1].Length - 1);

                if (iType == "int" || iType == "float") {
                    tSQL = arySQL[0] + ", " + iName + ") VALUES (" + arySQL[1] + ", '" + iValue + "')";
                }
                else {
                    tSQL = arySQL[0] + ", " + iName + ") VALUES (" + arySQL[1] + ", N'" + iValue + "')";
                }
            }
            else {
                if (iType == "int" || iType == "float") {
                    tSQL = "(" + iName + ") VALUES (" + "'" + iValue + "')";
                }
                else {
                    tSQL = "(" + iName + ") VALUES (" + "N'" + iValue + "')";
                }
            }

            return tSQL;
        }


        // 組 SQL，更新資料用 (SQL 字串, 資料庫欄位名, 變數值, 型別)
        /* $iType 型態可設定 int, float, str, datetime, date 五種
        範例：
        SQL = "";
        SQL = BSQL_U(SQL, "Coustomer_Id", "2345", "int");
        SQL = BSQL_U(SQL, "WebSite", "https://123456", "");
        SQL = BSQL_U(SQL, "WebName", "客戶網站", "");
        SQL = "UPDATE [TableName] SET " + SQL + "WHERE Num_Id = '123456'";
        */
        public string BSQL_U(string tSQL, string iName, string iValue, string iType = "") {
            if (iType.Length == 0) { iType = "str"; }

            if (iType.Length > 0) {
                iType = iType.ToLower();

                if (iType == "int" || iType == "float") {
                    if (iValue == "") {
                        iValue = "0";
                    }
                    else {
                        if (int.TryParse(iValue, out int num1) == false) {
                            return "資料：" + iValue + " 型別不符：" + iType;
                        }
                    }
                }

                if (iType != "int" && iType != "float" && iType != "str" && iType != "datetime" && iType != "date") {
                    return "資料：" + iValue + " 設定之型別：" + iType + " 不允許";
                }
            }

            if (tSQL.Length > 0) {
                if (iType == "int" || iType == "float") {
                    if (iValue.Length > 0) {
                        tSQL += ", " + iName + " = '" + iValue + "'";
                    }
                    else {
                        tSQL += ", " + iName + " = 0";
                    }
                }
                else {
                    tSQL += ", " + iName + " = N'" + iValue + "'";
                }
            }
            else {
                if (iType == "int" || iType == "float") {
                    if (iValue.Length > 0) {
                        tSQL = iName + " = '" + iValue + "'";
                    }
                    else {
                        tSQL = iName + " = 0";
                    }
                }
                else {
                    tSQL = iName + " = N'" + iValue + "'";
                }
            }

            return tSQL;
        }
        #endregion


        #region 通用功能
        // 格式化現在的時間 (yyyy-MM-dd HH:mm:ss)
        public string FormatNow() {
            return DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        }


        // 記錄 Log 副程式 (要記錄的訊息)
        public void LogMessage(string message = "") {
            try {
                if (appPath.Length == 0) { return; }
                if (appPath.EndsWith(pathSeparator) == false) { appPath += pathSeparator; }
                if (logDir.Length == 0) { logDir = "Log"; }

                // 檢查 Log 目錄
                if (Directory.Exists(appPath + logDir) == false) {
                    Directory.CreateDirectory(appPath + logDir);
                }

                // Log 訊息內容
                string logMsg = "";
                logMsg = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + message;

                // 寫入 Log
                FileStream fs = File.Open(appPath + logDir + pathSeparator + DateTime.Now.ToString("yyyy-MM-dd") + ".log", FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                StreamWriter sw = new StreamWriter(fs);
                sw.WriteLine(logMsg);
                sw.Dispose();
                fs.Dispose();

            }
            catch {
            }
        }


        // 顯示訊息 (要顯示的訊息, 要顯示的按鈕, 要顯示的圖示)
        public void ShowMessage(string msgContent, System.Windows.Forms.MessageBoxButtons msgButton, System.Windows.Forms.MessageBoxIcon msgIcon) {
            System.Windows.Forms.MessageBox.Show(msgContent, appName, msgButton, msgIcon);
        }


        // 顯示錯誤訊息 (發生錯誤的Function, 錯誤訊息)
        public void ShowErrMessage(string functionName, string errMessage) {
            System.Windows.Forms.MessageBox.Show("[ " + functionName + " ] 發生錯誤" + Environment.NewLine + errMessage, appName, System.Windows.Forms.MessageBoxButtons.OK, System.Windows.Forms.MessageBoxIcon.Error);
        }


        // AES-CBC 256 加密 (key, iv, 要加密的資料)
        public string AES_Encrypt(string key, string iv, string data) {
            try {
                byte[] sourceBytes = Encoding.UTF8.GetBytes(data);
                RijndaelManaged AES = new RijndaelManaged();
                AES.Key = Encoding.UTF8.GetBytes(key);
                AES.IV = Encoding.UTF8.GetBytes(iv);
                AES.Mode = CipherMode.CBC;
                AES.Padding = PaddingMode.PKCS7;
                ICryptoTransform transForm = AES.CreateEncryptor();

                return Convert.ToBase64String(transForm.TransformFinalBlock(sourceBytes, 0, sourceBytes.Length));

            }
            catch (Exception ex) {
                if (runtime_DeBug_Log == true) { LogMessage("[NETCommonClass.Basic.AES_Encrypt] 發生錯誤: " + ex.Message); }
                return "";
            }
        }


        // AES-CBC 256 解密 (key, iv, 要解密的資料)
        public string AES_Decrypt(string key, string iv, string data) {
            try {
                byte[] encryptBytes = Convert.FromBase64String(data);
                RijndaelManaged AES = new RijndaelManaged();
                AES.Key = Encoding.UTF8.GetBytes(key);
                AES.IV = Encoding.UTF8.GetBytes(iv);
                AES.Mode = CipherMode.CBC;
                AES.Padding = PaddingMode.PKCS7;
                ICryptoTransform transForm = AES.CreateDecryptor();

                return Encoding.UTF8.GetString(transForm.TransformFinalBlock(encryptBytes, 0, encryptBytes.Length));

            }
            catch (Exception ex) {
                if (runtime_DeBug_Log == true) { LogMessage("[NETCommonClass.Basic.AES_Decrypt] 發生錯誤: " + ex.Message); }
                return "";
            }
        }


        // MD5 加密 (要加密的字串)
        public string MD5(string str) {
            try {
                if (str.Length == 0) { return ""; }

                MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
                byte[] b = md5.ComputeHash(Encoding.UTF8.GetBytes(str));
                return BitConverter.ToString(b).Replace("-", string.Empty);

            }
            catch (Exception ex) {
                if (runtime_DeBug_Log == true) { LogMessage("[NETCommonClass.Basic.MD5] 發生錯誤: " + ex.Message); }
                return "";
            }
        }


        // 取得檔案的唯一識別碼 (檔案路徑與名稱, Hash類型)
        public string GetFileHashCode(string fileName, string hashType = "") {
            try {
                if (File.Exists(fileName) == false) { return ""; }

                if (hashType.Length == 0) { hashType = "MD5"; }
                hashType = hashType.ToUpper();
                if (hashType != "MD5" && hashType != "SHA256") { hashType = "SHA256"; }

                string result = "";

                if (hashType == "MD5") {
                    using (var md5 = System.Security.Cryptography.MD5.Create()) {
                        using (FileStream fs = File.OpenRead(fileName)) {
                            result = BitConverter.ToString(md5.ComputeHash(fs)).Replace("-", string.Empty).ToUpper();
                        }
                    }
                }
                else if (hashType == "SHA256") {
                    using (var sha256 = System.Security.Cryptography.SHA256Managed.Create()) {
                        using (FileStream fs = File.OpenRead(fileName))
                            result = BitConverter.ToString(sha256.ComputeHash(fs)).Replace("-", string.Empty).ToUpper();
                    }
                }

                return result;

            }
            catch (Exception ex) {
                if (runtime_DeBug_Log == true) { LogMessage("[NETCommonClass.Basic.GetFileHashCode] 發生錯誤: " + ex.Message); }
                return "";
            }
        }


        // 字串切割 (字串內容, 要切割的字串)
        public string[] Split(string source, string str) {
            try {
                var list = new List<string>();
                while (true) {
                    var index = source.IndexOf(str);
                    if (index < 0) { list.Add(source); break; }
                    var rs = source.Substring(0, index);
                    list.Add(rs);
                    source = source.Substring(index + str.Length);
                }

                return list.ToArray();

            }
            catch (Exception ex) {
                if (runtime_DeBug_Log == true) { LogMessage("[NETCommonClass.Basic.Split] 發生錯誤: " + ex.Message); }
                return null;
            }
        }


        // 取得用戶端 IP (網頁或應用程式 EXE 均適用)
        public string GetClientIP() {
            string result = "";

            // 先以網頁模式讀取 IP
            try {
                HttpContext context = HttpContext.Current;
                string ipAddress = context.Request.ServerVariables["HTTP_X_FORWARDED_FOR"];

                if (!string.IsNullOrEmpty(ipAddress)) {
                    string[] addresses = ipAddress.Split(',');
                    if (addresses.Length != 0) {
                        result = "" + addresses[0].ToString();
                    }
                }
                else {
                    result = "" + context.Request.ServerVariables["REMOTE_ADDR"].ToString();
                }
            }
            catch {
            }

            // 如果網頁模式沒有 IP，讀取本機 IP (for EXE)
            if (result.Length == 0) {
                try {
                    foreach (IPAddress IPA in Dns.GetHostAddresses(Dns.GetHostName())) {
                        if (IPA.AddressFamily.ToString() == "InterNetwork") {
                            result = IPA.ToString();
                            break;
                        }
                    }
                }
                catch {
                }
            }

            result = result.Replace("::1", "127.0.0.1");
            return result;
        }


        // 讀取 CSV 到 DataTable (CSV 實體路徑)
        public DataTable CsvToDataTable(string csvFilePath) {
            DataTable dt = new DataTable();
            if (File.Exists(csvFilePath) == false) { return dt; }

            try {
                DataColumn dc;
                DataRow dr;

                int intColCount = 0;
                bool blnFlag = true;
                string strLine;
                string[] aryLine;

                // 開啟與讀取 CSV
                StreamReader sr = new StreamReader(csvFilePath, Encoding.Default);

                while ((strLine = sr.ReadLine()) != null) {
                    aryLine = strLine.Split(new char[] { ',' });

                    // 給 DataTable 加上欄位名稱
                    if (blnFlag == true) {
                        blnFlag = false;
                        intColCount = aryLine.Length;
                        int col = 0;
                        for (int i = 0; i < aryLine.Length; i++) {
                            col = i + 1;
                            dc = new DataColumn(col.ToString());
                            dt.Columns.Add(dc);
                        }
                    }

                    // 將資料加入到 DataTable
                    dr = dt.NewRow();
                    for (int i = 0; i < intColCount; i++) {
                        dr[i] = aryLine[i];
                    }
                    dt.Rows.Add(dr);
                }

                // 關閉與釋放 CSV 檔
                sr.Close();
                sr = null;
                dc = null;
                dr = null;

                return dt;

            }
            catch (Exception ex) {
                if (runtime_DeBug_Log == true) { LogMessage("[NETCommonClass.Basic.CsvToDataTable] 發生錯誤: " + ex.Message); }
                return dt;
            }
        }


        // 產生指定位數的亂數值 (長度)
        public string GetRandomStr(int iLength) {
            string randomStr = "abcdefghijkmnpqrstxyzABCDEFGHJKLMNPQRSTUVXYZ0123456789";
            if (iLength < 0) { iLength = 6; }

            StringBuilder sb = new StringBuilder();
            Random r = new Random();
            int range = randomStr.Length;

            for (int i = 0; i < iLength; i++) {
                sb.Append(randomStr.Substring(r.Next(range), 1));
            }

            return sb.ToString();
        }
        #endregion


        #region 網路功能
        // 讀取前端傳送資料 (欄位名稱)
        public string GetRequest(string names, int maxLengs = 0) {
            try {
                string values = "";
                int lengs = 0;

                if (string.IsNullOrEmpty(names) == true) { return ""; }

                values = "" + HttpContext.Current.Request.Form[names].ToString();
                if (values.Length == 0) { values = "" + HttpContext.Current.Request.QueryString[names].ToString(); }

                values = values.Replace("'", "''");

                // 取限定長度的資料
                if (maxLengs == 0) { lengs = 0; }
                lengs = maxLengs;
                if (lengs >= 99999999) { lengs = 99999999; }

                if (lengs > 0) {
                    values = values.Trim();
                    if (values.Length > lengs) {
                        values = values.Substring(0, lengs);
                    }
                }

                return values;

            }
            catch (Exception ex) {
                if (runtime_DeBug_Log == true) { LogMessage("[NETCommonClass.Basic.GetRequest] 發生錯誤: " + ex.Message); }
                return "";
            }
        }


        // 網頁顯示訊息 (要顯示的訊息, 要跳轉的網址)
        public void ShowWebMessage(string message, string nextUrl = "") {
            try {
                message = message.Replace("'", @"\'");
                message = message.Replace("\n", @"\n");
                message = "alert('" + message + "');";
                if (nextUrl.Length > 0) { message += "window.top.location.href='" + nextUrl + "';"; }

                if (HttpContext.Current.CurrentHandler is System.Web.UI.Page) {
                    System.Web.UI.Page p = (System.Web.UI.Page)HttpContext.Current.CurrentHandler;
                    p.ClientScript.RegisterStartupScript(typeof(System.Web.UI.Page), "", message, true);
                }

            }
            catch (Exception ex) {
                if (runtime_DeBug_Log == true) { LogMessage("[NETCommonClass.Basic.ShowWebMessage] 發生錯誤: " + ex.Message); }
            }
        }


        // HTTP (methods, url, parame, header, jsonType, jsonData)
        public string HTTP(string methods, string url, Dictionary<string, string> postParameters = null, Dictionary<string, string> headers = null, bool jsonType = false, object jsonData = null) {
            try {
                if (methods.Length == 0) { methods = "POST"; }
                methods = methods.ToUpper();
                if (methods != "GET" && methods != "POST") { methods = "POST"; }

                // 如果有傳遞參數
                string postData = "";
                if (postParameters != null) {
                    System.Collections.Specialized.NameValueCollection datas = HttpUtility.ParseQueryString(string.Empty);
                    foreach (var items in postParameters) {
                        datas.Add(items.Key, HttpUtility.UrlEncode(items.Value));
                    }

                    // 附加隨機亂數，確保每次傳送在主機端不會有快取暫存
                    Random rands = new Random();
                    datas.Add("LibraryTimes", rands.Next(9999).ToString());
                    postData = datas.ToString();
                }

                // GET 傳遞參數
                if (methods == "GET") {
                    if (postData.Length > 0) {
                        url += "?" + postData;
                    }
                }

                // 建立 HTTP 物件
                ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                req.Method = methods;
                req.Proxy = null;
                req.KeepAlive = false;
                req.Timeout = 60000;
                req.Headers.Set("Pragma", "no-cache");

                // 是否有自訂 Header
                if (headers != null) {
                    foreach (var items in headers) {
                        req.Headers.Set(items.Key, items.Value);
                    }
                }

                // 是否有指定使用 JSON 的 ContentType
                if (jsonType == false) {
                    req.ContentType = "application/x-www-form-urlencoded; charset=UTF-8";
                }
                else {
                    req.ContentType = "application/json; charset=UTF-8";

                    // 如果有傳遞 JSON 物件，則取代 postData
                    if (jsonData != null) {
                        postData = jsonData.ToString();
                    }
                }

                // POST 傳遞參數
                if (methods == "POST") {
                    if (postData.Length > 0) {
                        byte[] aryBytes = Encoding.UTF8.GetBytes(postData);
                        req.ContentLength = aryBytes.Length;
                        Stream st = req.GetRequestStream();
                        st.Write(aryBytes, 0, aryBytes.Length);
                        st.Close();
                    }
                }

                // 發送 HTTP 與接收回傳值
                string result = "";
                HttpWebResponse resp = (HttpWebResponse)req.GetResponse();
                StreamReader sr = new StreamReader(resp.GetResponseStream(), Encoding.GetEncoding("UTF-8"));
                result = sr.ReadToEnd();

                // 釋放物件
                sr.Close();
                resp.Close();
                req = null;

                return result;

            }
            catch (Exception ex) {
                if (runtime_DeBug_Log == true) { LogMessage("[NETCommonClass.Basic.HTTP] 發生錯誤: " + ex.Message); }
                return ex.Message;
            }
        }


        // HTTP 上傳檔案 (要上傳的網址, 設定上傳檔案的名稱, 要上傳的檔案)
        public string HTTP_UploadFile(string postUrl, string postFieldName, string uploadFile) {
            try {
                string result = "";

                if (postUrl.Length == 0 || postFieldName.Length == 0 || uploadFile.Length == 0) { return ""; }
                if (File.Exists(uploadFile) == false) { return ""; }

                // HTTP 物件
                ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                HttpClient hc = new HttpClient();
                MultipartFormDataContent form = new MultipartFormDataContent();

                // 讀取要上傳的完整檔案內容
                FileStream fs = File.OpenRead(uploadFile);
                StreamContent sc = new StreamContent(fs);

                ByteArrayContent fileContent = new ByteArrayContent(sc.ReadAsByteArrayAsync().Result);
                fileContent.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse("multipart/form-data");

                fs.Close();
                fs.Dispose();

                // HTTP 檔案上傳並讀取回傳值
                form.Add(fileContent, postFieldName, Path.GetFileName(uploadFile));
                var response = hc.PostAsync(postUrl, form).Result;
                var responseBody = response.Content.ReadAsStringAsync();
                hc.Dispose();

                result = responseBody.Result.ToString();

                return result;

            }
            catch (Exception ex) {
                if (runtime_DeBug_Log == true) { LogMessage("[NETCommonClass.Basic.HTTP_UploadFile] 發生錯誤: " + ex.Message); }
                return "";
            }
        }


        // 發送 LINE Notify (要發送的收件者 token, 要發送的內容)
        public void LINE_Notify(string token, string message) {
            try {
                string url = "https://notify-api.line.me/api/notify";
                ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);

                req.Method = "POST";
                req.ContentType = "application/x-www-form-urlencoded";
                req.Headers.Set("Authorization", "Bearer " + token);

                message = "message=\r\n\r\n" + message;
                byte[] aryBytes = Encoding.UTF8.GetBytes(message);
                req.ContentLength = aryBytes.Length;
                Stream st = req.GetRequestStream();
                st.Write(aryBytes, 0, aryBytes.Length);
                st.Close();

                string result = "";
                HttpWebResponse resp = (HttpWebResponse)req.GetResponse();
                StreamReader sr = new StreamReader(resp.GetResponseStream(), Encoding.GetEncoding("UTF-8"));
                result = sr.ReadToEnd();

                sr.Close();
                resp.Close();
                req = null;

            }
            catch (Exception ex) {
                if (runtime_DeBug_Log == true) { LogMessage("[NETCommonClass.Basic.LINE_Notify] 發生錯誤: " + ex.Message); }
            }
        }
        #endregion




    }
}
