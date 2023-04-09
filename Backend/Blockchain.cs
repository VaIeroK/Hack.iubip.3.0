using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Data.SQLite;
using Dapper;

namespace Backend
{
    public class Block
    {
        public int Index { get; set; }
        public string Hash { get; set; }

        public Block()
        {
        }

        public Block(int index, string hash)
        {
            Index = (int)index;
            Hash = hash;
        }

        public Block(int index, string previousHash, BlockchainUser user)
        {
            user.Id = index;
            Index = index;
            Hash = CalculateHash(user.Password, previousHash);
        }

        public static string CalculateHash(string password, string previousHash)
        {
            string input = previousHash + password;
            using SHA256 hash = SHA256.Create();
            return Convert.ToHexString(hash.ComputeHash(Encoding.ASCII.GetBytes(input)));
        }
    }

    public class Blockchain
    {
        public List<Block> Chain { get; set; }
        SQLiteConnection connection;

        public Blockchain()
        {
            connection = DB.CreateDB("database.db");
            connection.Execute(@"CREATE TABLE IF NOT EXISTS Blockchain (
            Id INTEGER PRIMARY KEY, 
            Hash TEXT
            )");
            Chain = GetAllBlocks().ToList();
            if (Chain.Count() == 0)
                AddGenesisBlock();
        }

        public IEnumerable<Block> GetAllBlocks()
        {
            return connection.Query<Block>("SELECT * FROM Blockchain");
        }

        private void AddGenesisBlock()
        {
            BlockchainUser user = new BlockchainUser("jma_fucker", "1111");
            Block genesisBlock = new Block(0, "", user);
            connection.Execute("INSERT INTO Blockchain (Hash) VALUES (@Hash)", genesisBlock);
            Chain.Add(genesisBlock);
        }

        public void AddBlock(BlockchainUser user)
        {
            Block lastBlock = Chain[Chain.Count - 1];
            int index = lastBlock.Index + 1;
            string previousHash = lastBlock.Hash;
            Block block = new Block(index, previousHash, user);
            connection.Execute("INSERT INTO Blockchain (Hash) VALUES (@Hash)", block);
            Chain.Add(block);
        }
    }
}
