using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.SQLite;

namespace Backend
{
    public static class DB
    {
        public static SQLiteConnection CreateDB(string name)
        {
            if (!File.Exists(name))
                SQLiteConnection.CreateFile(name);
            var connection = new SQLiteConnection($"Data Source={name}");
            return connection;
        }
    }
}
