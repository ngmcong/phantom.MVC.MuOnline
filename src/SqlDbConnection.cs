using Microsoft.Data.SqlClient;
using System.Data;
using System.Data.Common;

namespace phantom.MVC.MuOnline
{
    public class SqlDbConnection() : IDisposable
    {
        private const string _connectionString = "Data Source=192.168.2.199;Initial Catalog=MuOnline;User ID=sa;Password=;TrustServerCertificate=True;";
        private readonly DbConnection dbConnection = new SqlConnection(_connectionString);
        private DbCommand? dbCommand;

        private void InitDbCommand(string query)
        {
            if (dbCommand == null)
            {
                dbCommand = new SqlCommand(query);
                dbCommand.Connection = dbConnection;
            }
            else dbCommand.CommandText = query;
            dbCommand.CommandType = System.Data.CommandType.Text;
        }

        public void OpenTransaction()
        {
            if (dbConnection.State != System.Data.ConnectionState.Open) dbConnection.Open();
            if (dbCommand == null) dbCommand = dbConnection.CreateCommand();
            dbCommand.Transaction = dbConnection.BeginTransaction();
        }

        public void RollbackTransaction()
        {
            dbCommand!.Transaction!.Rollback();
        }

        public void CommitTransaction()
        {
            dbCommand!.Transaction!.Commit();
        }

        public async Task<int> ExecuteNonQueryAsync(string query)
        {
            try
            {
                InitDbCommand(query);
                if (dbConnection.State != System.Data.ConnectionState.Open) await dbConnection.OpenAsync();
                return await dbCommand!.ExecuteNonQueryAsync();
            }
            catch
            {
                throw;
            }
        }

        public async Task<object?> ExecuteScalarAsync(string query)
        {
            try
            {
                InitDbCommand(query);
                if (dbConnection.State != System.Data.ConnectionState.Open) await dbConnection.OpenAsync();
                return await dbCommand!.ExecuteScalarAsync();
            }
            catch
            {
                throw;
            }
        }

        public DataTable Fill(string query)
        {
            try
            {
                InitDbCommand(query);
                DbDataAdapter dbDataAdapter = new SqlDataAdapter((SqlCommand)dbCommand!);
                DataTable dataTable = new DataTable();
                dbDataAdapter.Fill(dataTable);
                return dataTable;
            }
            catch
            {
                throw;
            }
        }

        public void Dispose()
        {
            if (dbCommand?.Transaction != null) dbCommand.Transaction.Dispose();
            dbCommand?.Dispose();
            dbConnection.Close();
            dbConnection.Dispose();
        }
    }
}
